/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_FIPS202_FIPS202_H
#define MLK_FIPS202_FIPS202_H
#include <stdint.h>

#include "sw/device/lib/crypto/include/sha3.h"
#include "mlkem/src/common.h"

#define SHAKE128_RATE 168

/* TODO: figure out the minimum value for this */
#define MLK_SHAKE128_MAX_INPUT_LENGTH 1024
typedef struct
{
  uint8_t input[MLK_SHAKE128_MAX_INPUT_LENGTH];
  size_t inlen;
  size_t pos;
} MLK_ALIGN mlk_shake128ctx;


/* TODO: mlkem-native currently operates on multiple Keccak states
 *       within the rejection sampling to allow efficient batching
 *       on CPUs with vector instructions. This is incompatible
 *       with using a Keccak accelerator (such as OT's KMAC) that
 *       holds the Keccak state internally.
 *       Currently we work around this by implementing repeated
 *       squeezing as regenerating all previous output.
 *       It would be better to add an option to mlkem-native
 *       that entirely disables batching which would be compatible
 *       with a Keccak accelerator with a single state.
 */
static MLK_INLINE mlk_shake128_absorb_once(mlk_shake128ctx *state, const uint8_t *input,
                              size_t inlen)
{
  if(inlen > MLK_SHAKE128_MAX_INPUT_LENGTH) return;
  state->inlen = inlen;
  mlk_memcpy(state->input, input, inlen);
  state->pos = 0;
}

static MLK_INLINE void mlk_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                mlk_shake128ctx *state)
{
  /* TODO: Eliminate this VLA; This will be cleaner with a proper squeeze API */
  uint8_t tmp[(nblocks + state->pos)*SHAKE128_RATE];

  otcrypto_hash_digest_t md = {
    .data = (uint32_t *)tmp,
    .len = sizeof(tmp) / 4,
    .mode = kOtcryptoHashXofModeShake256
  };

  otcrypto_const_byte_buf_t d = {
    .data = state->input,
    .len = state->inlen
  };

  otcrypto_shake128(d, &md);

  mlk_memcpy(output, tmp + state->pos * SHAKE128_RATE, nblocks * SHAKE128_RATE);
  state->pos += nblocks;
}

static MLK_INLINE void mlk_shake128_init(mlk_shake128ctx *state) { (void)state; }
static MLK_INLINE void mlk_shake128_release(mlk_shake128ctx *state)
{
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(state, sizeof(mlk_shake128ctx));
}

static MLK_INLINE void mlk_shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                  size_t inlen)
{
  otcrypto_hash_digest_t md = {
    .data = (uint32_t *)output,
    .len = outlen / 4,
    .mode = kOtcryptoHashXofModeShake256
  };

  otcrypto_const_byte_buf_t d = {
    .data = input,
    .len = inlen
  };

  otcrypto_shake256(d, &md);
}

static MLK_INLINE void mlk_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
{
  otcrypto_hash_digest_t md = {
    .data = (uint32_t *)output,
    .len = 32 / 4,
    .mode = kOtcryptoHashModeSha3_256
  };

  otcrypto_const_byte_buf_t d = {
    .data = input,
    .len = inlen
  };

  otcrypto_sha3_256(d, &md);
}

static MLK_INLINE void mlk_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
{
  otcrypto_hash_digest_t md = {
    .data = (uint32_t *)output,
    .len = 64 / 4,
    .mode = kOtcryptoHashModeSha3_512
  };

  otcrypto_const_byte_buf_t d = {
    .data = input,
    .len = inlen
  };

  otcrypto_sha3_512(d, &md);
}

#endif /* MLK_FIPS202_FIPS202_H */