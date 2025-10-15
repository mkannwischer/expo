#include <stdlib.h>
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/profile.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "sw/device/lib/crypto/impl/mlkem/mlkem_native_monobuild.h"

OTTF_DEFINE_TEST_CONFIG();

static void test_mlkem_native_512(void){
  uint64_t t0;
  uint8_t pk[MLKEM512_PUBLICKEYBYTES];
  uint8_t sk[MLKEM512_SECRETKEYBYTES];
  uint8_t ct[MLKEM512_CIPHERTEXTBYTES];
  uint8_t key_a[MLKEM512_BYTES];
  uint8_t key_b[MLKEM512_BYTES];

  uint8_t coins[2*MLKEM512_BYTES] = {0};
  uint8_t coinsE[MLKEM512_BYTES] = {1};

  const uint8_t expected_key[] = {
      0x5f, 0x5f, 0x8c, 0xf5, 0x7c, 0x34, 0xd4, 0x68, 0x06, 0xa2, 0xe9,
      0xc9, 0x28, 0xba, 0x10, 0x5a, 0x46, 0xf2, 0x67, 0x1a, 0xc7, 0x81,
      0xdf, 0xf1, 0x4a, 0xbb, 0x27, 0xea, 0x46, 0x06, 0x46, 0x3c};

  t0 = profile_start();
  mlkem512_keypair_derand(pk, sk, coins);
  profile_end_and_print(t0, "mlkem512_keypair_derand");

  t0 = profile_start();
  mlkem512_enc_derand(ct, key_b, pk, coinsE);
  profile_end_and_print(t0, "mlkem512_enc_derand");


  t0 = profile_start();
  mlkem512_dec(key_a, ct, sk);
  profile_end_and_print(t0, "mlkem512_dec");


  CHECK_ARRAYS_EQ(key_a, key_b, MLKEM512_BYTES);
  CHECK_ARRAYS_EQ(key_a, expected_key, MLKEM512_BYTES);
}

static void test_mlkem_native_768(void){
  uint64_t t0;
  uint8_t pk[MLKEM768_PUBLICKEYBYTES];
  uint8_t sk[MLKEM768_SECRETKEYBYTES];
  uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
  uint8_t key_a[MLKEM768_BYTES];
  uint8_t key_b[MLKEM768_BYTES];

  uint8_t coins[2*MLKEM768_BYTES] = {0};
  uint8_t coinsE[MLKEM768_BYTES] = {1};

  const uint8_t expected_key[] = {
      0x85, 0x21, 0xab, 0xc8, 0x14, 0xc7, 0x67, 0x70, 0x4f, 0xa6, 0x25,
      0xd9, 0x35, 0x95, 0xd0, 0x03, 0x79, 0xa8, 0xb3, 0x70, 0x35, 0x2c,
      0xa4, 0xba, 0xb3, 0xa6, 0x82, 0x46, 0x63, 0x0d, 0xb0, 0x8b};

  t0 = profile_start();
  mlkem768_keypair_derand(pk, sk, coins);
  profile_end_and_print(t0, "mlkem768_keypair_derand");

  t0 = profile_start();
  mlkem768_enc_derand(ct, key_b, pk, coinsE);
  profile_end_and_print(t0, "mlkem768_enc_derand");


  t0 = profile_start();
  mlkem768_dec(key_a, ct, sk);
  profile_end_and_print(t0, "mlkem768_dec");


  CHECK_ARRAYS_EQ(key_a, key_b, MLKEM768_BYTES);
  CHECK_ARRAYS_EQ(key_a, expected_key, MLKEM768_BYTES);
}

static void test_mlkem_native_1024(void){
  uint64_t t0;
  uint8_t pk[MLKEM1024_PUBLICKEYBYTES];
  uint8_t sk[MLKEM1024_SECRETKEYBYTES];
  uint8_t ct[MLKEM1024_CIPHERTEXTBYTES];
  uint8_t key_a[MLKEM1024_BYTES];
  uint8_t key_b[MLKEM1024_BYTES];

  uint8_t coins[2*MLKEM1024_BYTES] = {0};
  uint8_t coinsE[MLKEM1024_BYTES] = {1};

  const uint8_t expected_key[] = {
      0x30, 0x4d, 0xbe, 0x54, 0xd6, 0x6f, 0x80, 0x66, 0xc6, 0xa8, 0x1c,
      0x6b, 0x36, 0xc4, 0x48, 0x9b, 0xf9, 0xe6, 0x05, 0x79, 0x83, 0x3c,
      0x4e, 0xdc, 0x8a, 0xc7, 0x92, 0xe5, 0x73, 0x0d, 0xdd, 0x85};

  t0 = profile_start();
  mlkem1024_keypair_derand(pk, sk, coins);
  profile_end_and_print(t0, "mlkem1024_keypair_derand");

  t0 = profile_start();
  mlkem1024_enc_derand(ct, key_b, pk, coinsE);
  profile_end_and_print(t0, "mlkem1024_enc_derand");


  t0 = profile_start();
  mlkem1024_dec(key_a, ct, sk);
  profile_end_and_print(t0, "mlkem1024_dec");

  CHECK_ARRAYS_EQ(key_a, key_b, MLKEM1024_BYTES);
  CHECK_ARRAYS_EQ(key_a, expected_key, MLKEM1024_BYTES);
}


bool test_main(void) {

  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  test_mlkem_native_512();
  test_mlkem_native_768();
  test_mlkem_native_1024();
  

  return true;
}
