// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/drivers/kmac.h"

#include "sw/device/lib/base/abs_mmio.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/math.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/impl/status.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "kmac_regs.h"  // Generated.

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('d', 'k', 'c')

/**
 * Security strength values.
 *
 * These values corresponds to the half of the capacity of Keccak permutation.
 */
typedef enum kmac_security_str {
  kKmacSecurityStrength128 = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L128,
  kKmacSecurityStrength224 = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L224,
  kKmacSecurityStrength256 = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L256,
  kKmacSecurityStrength384 = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L384,
  kKmacSecurityStrength512 = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L512,
} kmac_security_str_t;

/**
 * List of supported KMAC modes.
 *
 * Each `kmac_operation_t` enumeration constant is a bitfield with the
 * following layout:
 * - Bit 0: kmac_en (Whether to enable KMAC datapath).
 * - Bit 1-2: Keccak hashing mode (e.g. SHA, SHAKE, or cSHAKE).
 */
typedef enum kmac_operation {
  kKmacOperationSha3 = KMAC_CFG_SHADOWED_MODE_VALUE_SHA3 << 1 | 0,
  kKmacOperationShake = KMAC_CFG_SHADOWED_MODE_VALUE_SHAKE << 1 | 0,
  kKmacOperationCshake = KMAC_CFG_SHADOWED_MODE_VALUE_CSHAKE << 1 | 0,
  kKmacOperationKmac = KMAC_CFG_SHADOWED_MODE_VALUE_CSHAKE << 1 | 1,
} kmac_operation_t;

/**
 * List of supported KMAC key sizes.
 */
typedef enum kmac_key_length {
  kKmacKeyLength128 = KMAC_KEY_LEN_LEN_VALUE_KEY128,
  kKmacKeyLength192 = KMAC_KEY_LEN_LEN_VALUE_KEY192,
  kKmacKeyLength256 = KMAC_KEY_LEN_LEN_VALUE_KEY256,
  kKmacKeyLength384 = KMAC_KEY_LEN_LEN_VALUE_KEY384,
  kKmacKeyLength512 = KMAC_KEY_LEN_LEN_VALUE_KEY512,
} kmac_key_len_t;

enum {
  kKmacBaseAddr = TOP_EARLGREY_KMAC_BASE_ADDR,
  kKmacCfgAddr = kKmacBaseAddr + KMAC_CFG_SHADOWED_REG_OFFSET,
  kKmacKeyShare0Addr = kKmacBaseAddr + KMAC_KEY_SHARE0_0_REG_OFFSET,
  kKmacKeyShare1Addr = kKmacBaseAddr + KMAC_KEY_SHARE1_0_REG_OFFSET,
  kKmacStateShareSize = KMAC_STATE_SIZE_BYTES / 2,
  kKmacStateShare0Addr = kKmacBaseAddr + KMAC_STATE_REG_OFFSET,
  kKmacStateShare1Addr =
      kKmacBaseAddr + KMAC_STATE_REG_OFFSET + kKmacStateShareSize,
};

// "KMAC" string in little endian
static const uint8_t kKmacFuncNameKMAC[] = {0x4b, 0x4d, 0x41, 0x43};

// We need 5 bytes at most for encoding the length of cust_str and func_name.
// That leaves 39 bytes for the string. We simply truncate it to 36 bytes.
OT_ASSERT_ENUM_VALUE(kKmacPrefixMaxSize, 4 * KMAC_PREFIX_MULTIREG_COUNT - 8);

// Check that KEY_SHARE registers form a continuous address space
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_1_REG_OFFSET,
                     KMAC_KEY_SHARE0_0_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_2_REG_OFFSET,
                     KMAC_KEY_SHARE0_1_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_3_REG_OFFSET,
                     KMAC_KEY_SHARE0_2_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_4_REG_OFFSET,
                     KMAC_KEY_SHARE0_3_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_5_REG_OFFSET,
                     KMAC_KEY_SHARE0_4_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_6_REG_OFFSET,
                     KMAC_KEY_SHARE0_5_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_7_REG_OFFSET,
                     KMAC_KEY_SHARE0_6_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_8_REG_OFFSET,
                     KMAC_KEY_SHARE0_7_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_9_REG_OFFSET,
                     KMAC_KEY_SHARE0_8_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_10_REG_OFFSET,
                     KMAC_KEY_SHARE0_9_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_11_REG_OFFSET,
                     KMAC_KEY_SHARE0_10_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_12_REG_OFFSET,
                     KMAC_KEY_SHARE0_11_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_13_REG_OFFSET,
                     KMAC_KEY_SHARE0_12_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_14_REG_OFFSET,
                     KMAC_KEY_SHARE0_13_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE0_15_REG_OFFSET,
                     KMAC_KEY_SHARE0_14_REG_OFFSET + 4);

OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_1_REG_OFFSET,
                     KMAC_KEY_SHARE1_0_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_2_REG_OFFSET,
                     KMAC_KEY_SHARE1_1_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_3_REG_OFFSET,
                     KMAC_KEY_SHARE1_2_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_4_REG_OFFSET,
                     KMAC_KEY_SHARE1_3_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_5_REG_OFFSET,
                     KMAC_KEY_SHARE1_4_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_6_REG_OFFSET,
                     KMAC_KEY_SHARE1_5_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_7_REG_OFFSET,
                     KMAC_KEY_SHARE1_6_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_8_REG_OFFSET,
                     KMAC_KEY_SHARE1_7_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_9_REG_OFFSET,
                     KMAC_KEY_SHARE1_8_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_10_REG_OFFSET,
                     KMAC_KEY_SHARE1_9_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_11_REG_OFFSET,
                     KMAC_KEY_SHARE1_10_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_12_REG_OFFSET,
                     KMAC_KEY_SHARE1_11_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_13_REG_OFFSET,
                     KMAC_KEY_SHARE1_12_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_14_REG_OFFSET,
                     KMAC_KEY_SHARE1_13_REG_OFFSET + 4);
OT_ASSERT_ENUM_VALUE(KMAC_KEY_SHARE1_15_REG_OFFSET,
                     KMAC_KEY_SHARE1_14_REG_OFFSET + 4);

// Ensure each PREFIX register is 4 bytes
OT_ASSERT_ENUM_VALUE(32, KMAC_PREFIX_PREFIX_FIELD_WIDTH);

/**
 * Get the rate of the current mode in 32-bit words.
 *
 * @param keccak_rate The keccak rate in 32-bit words.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t get_keccak_rate_words(size_t *keccak_rate) {
  uint32_t cfg_reg =
      abs_mmio_read32(kKmacBaseAddr + KMAC_CFG_SHADOWED_REG_OFFSET);
  uint32_t security_strength =
      bitfield_field32_read(cfg_reg, KMAC_CFG_SHADOWED_KSTRENGTH_FIELD);

  *keccak_rate = 0;
  // Since Keccak state is 1600 bits, rate is calculated with
  // rate = (1600 - 2*x) where x is the security strength (i.e. half the
  // capacity).
  switch (security_strength) {
    case kKmacSecurityStrength128:
      *keccak_rate = (1600 - 2 * 128) / 32;
      break;
    case kKmacSecurityStrength224:
      *keccak_rate = (1600 - 2 * 224) / 32;
      break;
    case kKmacSecurityStrength256:
      *keccak_rate = (1600 - 2 * 256) / 32;
      break;
    case kKmacSecurityStrength384:
      *keccak_rate = (1600 - 2 * 384) / 32;
      break;
    case kKmacSecurityStrength512:
      *keccak_rate = (1600 - 2 * 512) / 32;
      break;
    default:
      // Read an invalid value out of the hardware!
      return OTCRYPTO_FATAL_ERR;
  }
  HARDENED_CHECK_NE(keccak_rate, 0);

  return OTCRYPTO_OK;
}

/**
 * Return the matching enum of `kmac_key_len_t` for given key length.
 *
 * `key_len_enum` must not be NULL pointer.
 *
 * @param key_len The size of the key in bytes.
 * @param key_len_enum The corresponding enum value to be returned.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t kmac_get_key_len_bytes(size_t key_len,
                                       kmac_key_len_t *key_len_enum) {
  switch (key_len) {
    case 128 / 8:
      *key_len_enum = kKmacKeyLength128;
      break;
    case 192 / 8:
      *key_len_enum = kKmacKeyLength192;
      break;
    case 256 / 8:
      *key_len_enum = kKmacKeyLength256;
      break;
    case 384 / 8:
      *key_len_enum = kKmacKeyLength384;
      break;
    case 512 / 8:
      *key_len_enum = kKmacKeyLength512;
      break;
    default:
      return OTCRYPTO_BAD_ARGS;
  }
  return OTCRYPTO_OK;
}

status_t kmac_hwip_default_configure(void) {
  // Ensure that the entropy complex is initialized.
  HARDENED_TRY(entropy_complex_check());

  uint32_t status_reg = abs_mmio_read32(kKmacBaseAddr + KMAC_STATUS_REG_OFFSET);

  // Check that core is not in fault state
  if (bitfield_bit32_read(status_reg, KMAC_STATUS_ALERT_FATAL_FAULT_BIT)) {
    return OTCRYPTO_FATAL_ERR;
  }
  if (bitfield_bit32_read(status_reg,
                          KMAC_STATUS_ALERT_RECOV_CTRL_UPDATE_ERR_BIT)) {
    return OTCRYPTO_RECOV_ERR;
  }
  // Check that core is not busy
  if (!bitfield_bit32_read(status_reg, KMAC_STATUS_SHA3_IDLE_BIT)) {
    return OTCRYPTO_RECOV_ERR;
  }

  // Check that there is no err pending in intr state
  uint32_t intr_state =
      abs_mmio_read32(kKmacBaseAddr + KMAC_INTR_STATE_REG_OFFSET);
  if (bitfield_bit32_read(intr_state, KMAC_INTR_STATE_KMAC_ERR_BIT)) {
    return OTCRYPTO_RECOV_ERR;
  }

  // Check CFG.regwen
  uint32_t cfg_regwen =
      abs_mmio_read32(kKmacBaseAddr + KMAC_CFG_REGWEN_REG_OFFSET);
  if (!bitfield_bit32_read(cfg_regwen, KMAC_CFG_REGWEN_EN_BIT)) {
    return OTCRYPTO_RECOV_ERR;
  }

  // Keep err interrupt disabled
  uint32_t intr_reg = KMAC_INTR_ENABLE_REG_RESVAL;
  intr_reg = bitfield_bit32_write(intr_reg, KMAC_INTR_ENABLE_KMAC_ERR_BIT, 0);
  abs_mmio_write32(kKmacBaseAddr + KMAC_INTR_ENABLE_REG_OFFSET, intr_reg);

  // Configure max for entropy period (use UINT32_MAX and let bitfield clamp
  // them to their bitfield)
  // TODO: determine ideal values for this.
  uint32_t entropy_period = KMAC_ENTROPY_PERIOD_REG_RESVAL;
  entropy_period = bitfield_field32_write(
      entropy_period, KMAC_ENTROPY_PERIOD_PRESCALER_FIELD, UINT32_MAX);
  entropy_period = bitfield_field32_write(
      entropy_period, KMAC_ENTROPY_PERIOD_WAIT_TIMER_FIELD, UINT32_MAX);
  abs_mmio_write32(kKmacBaseAddr + KMAC_ENTROPY_PERIOD_REG_OFFSET,
                   entropy_period);

  // Configure max for hash threshold (use UINT32_MAX and let bitfield clamp
  // them to their bitfield)
  // TODO: determine ideal values for this.
  uint32_t entropy_hash_threshold =
      KMAC_ENTROPY_REFRESH_THRESHOLD_SHADOWED_REG_RESVAL;
  entropy_hash_threshold = bitfield_field32_write(
      entropy_hash_threshold,
      KMAC_ENTROPY_REFRESH_THRESHOLD_SHADOWED_THRESHOLD_FIELD, UINT32_MAX);
  abs_mmio_write32(
      kKmacBaseAddr + KMAC_ENTROPY_REFRESH_THRESHOLD_SHADOWED_REG_OFFSET,
      entropy_hash_threshold);

  // Configure CFG
  uint32_t cfg_reg = KMAC_CFG_SHADOWED_REG_RESVAL;
  // Little_endian
  cfg_reg =
      bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_MSG_ENDIANNESS_BIT, 0);
  cfg_reg =
      bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_STATE_ENDIANNESS_BIT, 0);

  // Sideload: off, default key comes from SW
  cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_SIDELOAD_BIT, 0);

  // Entropy mode: EDN
  cfg_reg =
      bitfield_field32_write(cfg_reg, KMAC_CFG_SHADOWED_ENTROPY_MODE_FIELD,
                             KMAC_CFG_SHADOWED_ENTROPY_MODE_VALUE_EDN_MODE);

  // Use quality randomness for message blocks too
  cfg_reg = bitfield_bit32_write(cfg_reg,
                                 KMAC_CFG_SHADOWED_ENTROPY_FAST_PROCESS_BIT, 1);
  // Do not remask message blocks
  cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_MSG_MASK_BIT, 0);

  // Mark entropy source as ready
  cfg_reg =
      bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_ENTROPY_READY_BIT, 1);
  // Unsupported modes: disabled
  cfg_reg = bitfield_bit32_write(
      cfg_reg, KMAC_CFG_SHADOWED_EN_UNSUPPORTED_MODESTRENGTH_BIT, 0);

  abs_mmio_write32_shadowed(kKmacBaseAddr + KMAC_CFG_SHADOWED_REG_OFFSET,
                            cfg_reg);

  return OTCRYPTO_OK;
}

/**
 * Wait until given status bit is set.
 *
 * Loops until the `bit_position` of status register reaches the value
 * `bit_value`.
 * @param bit_position The bit position in the status register.
 * @param bit_value Whether it should wait for 0 or 1.
 * @return Error status.
 */
OT_WARN_UNUSED_RESULT
static status_t wait_status_bit(uint32_t bit_position, bool bit_value) {
  if (bit_position > 31) {
    return OTCRYPTO_BAD_ARGS;
  }

  while (true) {
    uint32_t reg = abs_mmio_read32(kKmacBaseAddr + KMAC_STATUS_REG_OFFSET);
    if (bitfield_bit32_read(reg, KMAC_STATUS_ALERT_FATAL_FAULT_BIT)) {
      return OTCRYPTO_FATAL_ERR;
    }
    if (bitfield_bit32_read(reg, KMAC_STATUS_ALERT_RECOV_CTRL_UPDATE_ERR_BIT)) {
      return OTCRYPTO_RECOV_ERR;
    }
    if (bitfield_bit32_read(reg, bit_position) == bit_value) {
      return OTCRYPTO_OK;
    }
  }
}

/**
 * Returns the minimum positive number of bytes needed to encode the value.
 *
 * Note that if `value` is zero, the result will be 1; this matches
 * `right_encode` and `left_encode` from NIST SP800-185, which require the
 * number of bytes to be strictly positive.
 *
 * This routine is not constant-time and should not be used for secret values.
 *
 * @param value
 */
static uint8_t byte_len(uint32_t value) {
  uint8_t len = 0;
  do {
    value >>= 8;
    len++;
  } while (value > 0);
  return len;
}

/**
 * Set the prefix registers in the KMAC hardware block.
 *
 * The caller must ensure that the hardware is idle. Returns an error if the
 * combined size of customization string and the function name must not exceed
 * `kKmacPrefixMaxSize`.
 *
 * @param func_name Function name input in cSHAKE.
 * @param func_name_bytelen Function name input length in bytes.
 * @param cust_str Customization string input in cSHAKE.
 * @param cust_str_bytelen Customization string input length in bytes.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t set_prefix_regs(const unsigned char *func_name,
                                size_t func_name_bytelen,
                                const unsigned char *cust_str,
                                size_t cust_str_bytelen) {
  // Check if the lengths will fit in the prefix registers, including checking
  // for overflow.
  if (func_name_bytelen + cust_str_bytelen > kKmacPrefixMaxSize ||
      func_name_bytelen > UINT32_MAX - cust_str_bytelen) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Initialize so that trailing bytes are set to zero.
  uint32_t prefix[KMAC_PREFIX_MULTIREG_COUNT];
  memset(prefix, 0, sizeof(prefix));
  unsigned char *prefix_bytes = (unsigned char *)prefix;

  // Encode the length of the function name parameter using `left_encode`.
  uint32_t func_name_bitlen = 8 * func_name_bytelen;
  uint8_t func_name_bitlen_nbytes = byte_len(func_name_bitlen);
  func_name_bitlen = __builtin_bswap32(func_name_bitlen);
  unsigned char *func_name_bitlen_ptr = (unsigned char *)&func_name_bitlen;
  func_name_bitlen_ptr += sizeof(uint32_t) - func_name_bitlen_nbytes;
  memcpy(prefix_bytes, &func_name_bitlen_nbytes, 1);
  prefix_bytes++;
  memcpy(prefix_bytes, func_name_bitlen_ptr, func_name_bitlen_nbytes);
  prefix_bytes += func_name_bitlen_nbytes;

  // Write the function name.
  memcpy(prefix_bytes, func_name, func_name_bytelen);
  prefix_bytes += func_name_bytelen;

  // Encode the length of the customization string parameter using
  // `left_encode`.
  uint32_t cust_str_bitlen = 8 * cust_str_bytelen;
  uint8_t cust_str_bitlen_nbytes = byte_len(cust_str_bitlen);
  cust_str_bitlen = __builtin_bswap32(cust_str_bitlen);
  unsigned char *cust_str_bitlen_ptr = (unsigned char *)&cust_str_bitlen;
  cust_str_bitlen_ptr += sizeof(uint32_t) - cust_str_bitlen_nbytes;
  memcpy(prefix_bytes, &cust_str_bitlen_nbytes, 1);
  prefix_bytes++;
  memcpy(prefix_bytes, cust_str_bitlen_ptr, cust_str_bitlen_nbytes);
  prefix_bytes += cust_str_bitlen_nbytes;

  // Write the customization string.
  memcpy(prefix_bytes, cust_str, cust_str_bytelen);
  prefix_bytes += cust_str_bytelen;

  // Copy into KMAC's prefix registers.
  for (size_t i = 0; i < KMAC_PREFIX_MULTIREG_COUNT; i++) {
    abs_mmio_write32(
        kKmacBaseAddr + KMAC_PREFIX_0_REG_OFFSET + i * sizeof(uint32_t),
        prefix[i]);
  }

  return OTCRYPTO_OK;
}

/**
 * Initializes the KMAC configuration and starts the operation.
 *
 * In particular, this function sets the CFG register of KMAC for given
 * `operation_type`. The struct type kmac_operation_t is defined in a way that
 * each field inherently implies a fixed security strength (i.e. half of Keccak
 * capacity). For instance, if we want to run SHA-3 with 224-bit digest size,
 * then `operation_type` = kSHA3_224.
 *
 * `hw_backed` must be either `kHardenedBoolFalse` or `kHardenedBoolTrue`. For
 * other values, this function returns an error.
 * For KMAC operations, if `hw_backed = kHardenedBoolTrue` the sideloaded key
 * coming from Keymgr is used. If `hw_backed = kHardenedBoolFalse`, the key
 * configured by SW is used.
 *
 * For non-KMAC operations, the value of `hw_backed` can be either of
 * `kHardenedBoolFalse` or `kHardenedBoolTrue`. It is recommended to set it to
 * `kHardenedBoolFalse` for consistency.
 *
 * This function issues the `start` command to KMAC, so any additional
 * necessary configuration registers (e.g. key block) must be written before
 * calling this.
 *
 * @param operation The chosen operation, see kmac_operation_t struct.
 * @param security_str Security strength for KMAC (128 or 256).
 * @param hw_backed Whether the key comes from the sideload port.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t start(kmac_operation_t operation,
                      kmac_security_str_t security_str,
                      hardened_bool_t hw_backed) {
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_IDLE_BIT, 1));

  // If the operation is KMAC, ensure that the entropy complex has been
  // initialized for masking.
  if (operation == kKmacOperationKmac) {
    HARDENED_TRY(entropy_complex_check());
  }

  // We need to preserve some bits of CFG register, such as:
  // entropy_mode, entropy_ready etc. On the other hand, some bits
  // need to be reset for each invocation.
  uint32_t cfg_reg =
      abs_mmio_read32(kKmacBaseAddr + KMAC_CFG_SHADOWED_REG_OFFSET);

  // Make sure kmac_en and sideload bits of CFG are reset at each invocation
  // These bits should be set to 1 only if needed by the rest of the code
  // in this function.
  cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_KMAC_EN_BIT, 0);
  if (hw_backed == kHardenedBoolTrue) {
    cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_SIDELOAD_BIT, 1);
  } else if (hw_backed == kHardenedBoolFalse) {
    cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_SIDELOAD_BIT, 0);
  } else {
    return OTCRYPTO_BAD_ARGS;
  };

  // operation bit fields: Bit 0: `kmac_en`, Bit 1-2: `mode`
  cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_KMAC_EN_BIT,
                                 operation & 1);
  cfg_reg = bitfield_field32_write(cfg_reg, KMAC_CFG_SHADOWED_MODE_FIELD,
                                   operation >> 1);

  cfg_reg = bitfield_field32_write(cfg_reg, KMAC_CFG_SHADOWED_KSTRENGTH_FIELD,
                                   security_str);
  abs_mmio_write32_shadowed(kKmacBaseAddr + KMAC_CFG_SHADOWED_REG_OFFSET,
                            cfg_reg);

  // Issue the `start` command.
  uint32_t cmd_reg = KMAC_CMD_REG_RESVAL;
  cmd_reg = bitfield_field32_write(cmd_reg, KMAC_CMD_CMD_FIELD,
                                   KMAC_CMD_CMD_VALUE_START);
  abs_mmio_write32(kKmacBaseAddr + KMAC_CMD_REG_OFFSET, cmd_reg);
  return OTCRYPTO_OK;
}

/**
 * Update the key registers with given key shares.
 *
 * Returns an error if the key byte length is not one of the acceptable values:
 * 16, 24, 32, 40, or 48.
 *
 * @param key The input key passed as a struct.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t write_key_block(kmac_blinded_key_t *key) {
  kmac_key_len_t key_len_enum;
  HARDENED_TRY(kmac_get_key_len_bytes(key->len, &key_len_enum));

  uint32_t key_len_reg = bitfield_field32_write(
      KMAC_KEY_LEN_REG_RESVAL, KMAC_KEY_LEN_LEN_FIELD, key_len_enum);
  abs_mmio_write32(kKmacBaseAddr + KMAC_KEY_LEN_REG_OFFSET, key_len_reg);

  // Write key shares one at a time (so consecutive writes don't use
  // corresponding shares).
  // TODO: randomize write order.
  for (size_t i = 0; i < (key->len / sizeof(uint32_t)); i++) {
    abs_mmio_write32(kKmacKeyShare0Addr + i * sizeof(uint32_t), key->share0[i]);
  }
  for (size_t i = 0; i < (key->len / sizeof(uint32_t)); i++) {
    abs_mmio_write32(kKmacKeyShare1Addr + i * sizeof(uint32_t), key->share1[i]);
  }

  return OTCRYPTO_OK;
}

void kmac_process(void) {
  uint32_t cmd_reg = KMAC_CMD_REG_RESVAL;
  cmd_reg = bitfield_field32_write(cmd_reg, KMAC_CMD_CMD_FIELD,
                                   KMAC_CMD_CMD_VALUE_PROCESS);
  abs_mmio_write32(kKmacBaseAddr + KMAC_CMD_REG_OFFSET, cmd_reg);
}

status_t kmac_absorb(const uint8_t *message, size_t message_len) {
  // Block until KMAC is ready to absorb input.
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_ABSORB_BIT, 1));

  // Begin by writing a one byte at a time until the data is aligned.
  size_t i = 0;
  for (; misalignment32_of((uintptr_t)(&message[i])) > 0 && i < message_len;
       i++) {
    HARDENED_TRY(wait_status_bit(KMAC_STATUS_FIFO_FULL_BIT, 0));
    abs_mmio_write8(kKmacBaseAddr + KMAC_MSG_FIFO_REG_OFFSET, message[i]);
  }

  // Write one word at a time as long as there is a full word available.
  for (; i + sizeof(uint32_t) <= message_len; i += sizeof(uint32_t)) {
    HARDENED_TRY(wait_status_bit(KMAC_STATUS_FIFO_FULL_BIT, 0));
    uint32_t next_word = read_32(&message[i]);
    abs_mmio_write32(kKmacBaseAddr + KMAC_MSG_FIFO_REG_OFFSET, next_word);
  }

  // For the last few bytes, we need to write one byte at a time again.
  for (; i < message_len; i++) {
    HARDENED_TRY(wait_status_bit(KMAC_STATUS_FIFO_FULL_BIT, 0));
    abs_mmio_write8(kKmacBaseAddr + KMAC_MSG_FIFO_REG_OFFSET, message[i]);
  }
  return OTCRYPTO_OK;
}

/**
 * Write the digest length for KMAC operations.
 *
 * Expects input to have already been absorbed by the KMAC block. Writes result
 * directly into the message FIFO.
 *
 * Corresponds to `right_encode` in NIST SP800-185. Although that document
 * allows encoding values up to 2^2040, this driver only supports digests with
 * a bit-length up to 2^32 and returns an error if the word length is too big.
 *
 * @param digest_wordlen Length of the digest in 32-bit words.
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t encode_digest_length(size_t digest_wordlen) {
  if (digest_wordlen > (UINT32_MAX / (8 * sizeof(uint32_t)))) {
    return OTCRYPTO_BAD_ARGS;
  }
  uint32_t digest_bitlen = 8 * sizeof(uint32_t) * digest_wordlen;

  // Write the number of bits in big-endian order, using only as many bytes as
  // strictly required.
  unsigned char *bitlen_ptr = (unsigned char *)&digest_bitlen;
  uint8_t nbytes = byte_len(digest_bitlen);
  for (uint8_t i = 0; i < nbytes; i++) {
    abs_mmio_write8(kKmacBaseAddr + KMAC_MSG_FIFO_REG_OFFSET,
                    bitlen_ptr[nbytes - 1 - i]);
  }

  abs_mmio_write8(kKmacBaseAddr + KMAC_MSG_FIFO_REG_OFFSET, nbytes);
  return OTCRYPTO_OK;
}

/**
 * Read raw output from a SHA-3, SHAKE, cSHAKE, or KMAC operation.
 *
 * This is an internal operation that trusts its input; it does not check that
 * the number of words is within the Keccak rate. It simply reads the requested
 * number of words from the state registers. The caller is responsible for
 * ensuring enough data is available.
 *
 * Blocks until the squeeze bit goes high before reading.
 *
 * The caller must ensure that there is an amount of space matching the Keccak
 * rate times the number of blocks available at `share0`. If `nwords` is 0,
 * both shares are ignored and may be NULL. If `read_masked` is set, there must
 * also be the same amount of space available at `share1`; otherwise, `share1`
 * is ignored and may be NULL.
 *
 * @param nwords Number of words to read.
 * @param read_masked Whether to return the digest in two shares.
 * @param[out] share0 Destination for output (share if `read_masked`).
 * @param[out] share1 Destination for share of output (if `read_masked`).
 * @return Error code.
 */
OT_WARN_UNUSED_RESULT
static status_t read_state(size_t nwords, hardened_bool_t read_masked,
                           uint32_t *share0, uint32_t *share1) {
  // Poll the status register until in the 'squeeze' state.
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_SQUEEZE_BIT, 1));

  if (launder32(read_masked) == kHardenedBoolTrue) {
    HARDENED_CHECK_EQ(read_masked, kHardenedBoolTrue);

    // Read the digest into each share in turn. Do this in separate loops so
    // corresponding shares aren't handled close together.
    // TODO: randomize read order
    for (size_t offset = 0; offset < nwords; offset++) {
      share0[offset] =
          abs_mmio_read32(kKmacStateShare0Addr + offset * sizeof(uint32_t));
    }
    // TODO: randomize read order
    for (size_t offset = 0; offset < nwords; offset++) {
      share1[offset] =
          abs_mmio_read32(kKmacStateShare1Addr + offset * sizeof(uint32_t));
    }
  } else {
    // Skip right to the hardened check here instead of returning
    // `OTCRYPTO_BAD_ARGS` if the value is not `kHardenedBoolFalse`; this
    // value always comes from within the cryptolib, so we expect it to be
    // valid and should be suspicious if it's not.
    HARDENED_CHECK_EQ(read_masked, kHardenedBoolFalse);

    // Unmask the digest as we read it.
    for (size_t offset = 0; offset < nwords; offset++) {
      share0[offset] =
          abs_mmio_read32(kKmacStateShare0Addr + offset * sizeof(uint32_t));
      share0[offset] ^=
          abs_mmio_read32(kKmacStateShare1Addr + offset * sizeof(uint32_t));
    }
  }

  return OTCRYPTO_OK;
}

status_t kmac_squeeze_blocks(size_t nblocks, hardened_bool_t read_masked,
                             uint32_t *blocks_share0, uint32_t *blocks_share1) {
  size_t keccak_rate_words;
  HARDENED_TRY(get_keccak_rate_words(&keccak_rate_words));

  size_t i = 0;
  for (; launder32(i) < nblocks; i++) {
    HARDENED_TRY(read_state(keccak_rate_words, read_masked, blocks_share0,
                            blocks_share1));
    blocks_share0 += keccak_rate_words;
    if (read_masked == kHardenedBoolTrue) {
      blocks_share1 += keccak_rate_words;
    }

    // Issue `CMD.RUN` to generate more state.
    uint32_t cmd_reg = KMAC_CMD_REG_RESVAL;
    cmd_reg = bitfield_field32_write(cmd_reg, KMAC_CMD_CMD_FIELD,
                                     KMAC_CMD_CMD_VALUE_RUN);
    abs_mmio_write32(kKmacBaseAddr + KMAC_CMD_REG_OFFSET, cmd_reg);
  }
  HARDENED_CHECK_EQ(i, nblocks);

  return OTCRYPTO_OK;
}

status_t kmac_squeeze_end(size_t digest_wordlen, hardened_bool_t read_masked,
                          uint32_t *digest_share0, uint32_t *digest_share1) {
  // First, squeeze any full blocks.
  size_t keccak_rate_words;
  HARDENED_TRY(get_keccak_rate_words(&keccak_rate_words));
  size_t nblocks = digest_wordlen / keccak_rate_words;
  HARDENED_TRY(
      kmac_squeeze_blocks(nblocks, read_masked, digest_share0, digest_share1));

  size_t remaining_words = digest_wordlen % keccak_rate_words;
  HARDENED_TRY(
      read_state(remaining_words, read_masked, digest_share0, digest_share1));

  // Send the `done` command so that KMAC goes back to idle mode.
  uint32_t cmd_reg = KMAC_CMD_REG_RESVAL;
  cmd_reg = bitfield_field32_write(cmd_reg, KMAC_CMD_CMD_FIELD,
                                   KMAC_CMD_CMD_VALUE_DONE);
  abs_mmio_write32(kKmacBaseAddr + KMAC_CMD_REG_OFFSET, cmd_reg);

  return OTCRYPTO_OK;
}

status_t kmac_shake128_start(void) {
  return start(kKmacOperationShake, kKmacSecurityStrength128,
               /*hw_backed=*/kHardenedBoolFalse);
}

status_t kmac_shake256_start(void) {
  return start(kKmacOperationShake, kKmacSecurityStrength256,
               /*hw_backed=*/kHardenedBoolFalse);
}

/**
 * Perform a one-shot SHA3, SHAKE, or cSHAKE operation.
 *
 * Do not use this routine for KMAC operations.
 *
 * @param operation Hash function to perform.
 * @param strength Security strength parameter.
 * @param message Message data to hash.
 * @param message_len Length of message data in bytes.
 * @param digest_wordlen Length of digest in words.
 * @param[out] digest Computed digest.
 * @return OK or error.
 */
OT_WARN_UNUSED_RESULT
static status_t hash(kmac_operation_t operation, kmac_security_str_t strength,
                     const uint8_t *message, size_t message_len,
                     size_t digest_wordlen, uint32_t *digest) {
  // Note: to save code size, we check for null pointers here instead of
  // separately for every different Keccak hash operation.
  if (digest == NULL || (message == NULL && message_len != 0)) {
    return OTCRYPTO_BAD_ARGS;
  }

  HARDENED_TRY(start(operation, strength, /*hw_backed=*/kHardenedBoolFalse));
  HARDENED_TRY(kmac_absorb(message, message_len));
  kmac_process();
  return kmac_squeeze_end(digest_wordlen, /*read_masked=*/kHardenedBoolFalse,
                          digest, NULL);
}

inline status_t kmac_sha3_224(const uint8_t *message, size_t message_len,
                              uint32_t *digest) {
  return hash(kKmacOperationSha3, kKmacSecurityStrength224, message,
              message_len, kKmacSha3224DigestWords, digest);
}

inline status_t kmac_sha3_256(const uint8_t *message, size_t message_len,
                              uint32_t *digest) {
  return hash(kKmacOperationSha3, kKmacSecurityStrength256, message,
              message_len, kKmacSha3256DigestWords, digest);
}

inline status_t kmac_sha3_384(const uint8_t *message, size_t message_len,
                              uint32_t *digest) {
  return hash(kKmacOperationSha3, kKmacSecurityStrength384, message,
              message_len, kKmacSha3384DigestWords, digest);
}

inline status_t kmac_sha3_512(const uint8_t *message, size_t message_len,
                              uint32_t *digest) {
  return hash(kKmacOperationSha3, kKmacSecurityStrength512, message,
              message_len, kKmacSha3512DigestWords, digest);
}

inline status_t kmac_shake_128(const uint8_t *message, size_t message_len,
                               uint32_t *digest, size_t digest_len) {
  return hash(kKmacOperationShake, kKmacSecurityStrength128, message,
              message_len, digest_len, digest);
}

inline status_t kmac_shake_256(const uint8_t *message, size_t message_len,
                               uint32_t *digest, size_t digest_len) {
  return hash(kKmacOperationShake, kKmacSecurityStrength256, message,
              message_len, digest_len, digest);
}

inline status_t kmac_cshake_128(const uint8_t *message, size_t message_len,
                                const unsigned char *func_name,
                                size_t func_name_len,
                                const unsigned char *cust_str,
                                size_t cust_str_len, uint32_t *digest,
                                size_t digest_len) {
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_IDLE_BIT, 1));
  HARDENED_TRY(
      set_prefix_regs(func_name, func_name_len, cust_str, cust_str_len));
  return hash(kKmacOperationCshake, kKmacSecurityStrength128, message,
              message_len, digest_len, digest);
}

inline status_t kmac_cshake_256(const uint8_t *message, size_t message_len,
                                const unsigned char *func_name,
                                size_t func_name_len,
                                const unsigned char *cust_str,
                                size_t cust_str_len, uint32_t *digest,
                                size_t digest_len) {
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_IDLE_BIT, 1));
  HARDENED_TRY(
      set_prefix_regs(func_name, func_name_len, cust_str, cust_str_len));
  return hash(kKmacOperationCshake, kKmacSecurityStrength256, message,
              message_len, digest_len, digest);
}

inline status_t kmac_kmac_128(kmac_blinded_key_t *key,
                              hardened_bool_t masked_digest,
                              const uint8_t *message, size_t message_len,
                              const unsigned char *cust_str,
                              size_t cust_str_len, uint32_t *digest,
                              size_t digest_len) {
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_IDLE_BIT, 1));
  HARDENED_TRY(write_key_block(key));
  HARDENED_TRY(set_prefix_regs(kKmacFuncNameKMAC, sizeof(kKmacFuncNameKMAC),
                               cust_str, cust_str_len));
  HARDENED_TRY(
      start(kKmacOperationKmac, kKmacSecurityStrength128, key->hw_backed));

  HARDENED_TRY(kmac_absorb(message, message_len));
  HARDENED_TRY(encode_digest_length(digest_len));
  kmac_process();

  return kmac_squeeze_end(digest_len, masked_digest, digest,
                          digest + digest_len);
}

inline status_t kmac_kmac_256(kmac_blinded_key_t *key,
                              hardened_bool_t masked_digest,
                              const uint8_t *message, size_t message_len,
                              const unsigned char *cust_str,
                              size_t cust_str_len, uint32_t *digest,
                              size_t digest_len) {
  HARDENED_TRY(wait_status_bit(KMAC_STATUS_SHA3_IDLE_BIT, 1));
  HARDENED_TRY(write_key_block(key));
  HARDENED_TRY(set_prefix_regs(kKmacFuncNameKMAC, sizeof(kKmacFuncNameKMAC),
                               cust_str, cust_str_len));
  HARDENED_TRY(
      start(kKmacOperationKmac, kKmacSecurityStrength256, key->hw_backed));

  HARDENED_TRY(kmac_absorb(message, message_len));
  HARDENED_TRY(encode_digest_length(digest_len));
  kmac_process();

  return kmac_squeeze_end(digest_len, masked_digest, digest,
                          digest + digest_len);
}
