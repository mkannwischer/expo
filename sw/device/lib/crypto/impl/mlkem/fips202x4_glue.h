/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_FIPS202_FIPS202X4_H
#define MLK_FIPS202_FIPS202X4_H

#include "mlkem-native/src/common.h"
#include "fips202_glue.h"

/* Context for non-incremental API */
typedef struct
{
  mlk_shake128ctx ctx[4];
} MLK_ALIGN mlk_shake128x4ctx;

static MLK_INLINE void mlk_shake128x4_absorb_once(mlk_shake128x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
{
  mlk_shake128_absorb_once(&state->ctx[0], in0, inlen);
  mlk_shake128_absorb_once(&state->ctx[1], in1, inlen);
  mlk_shake128_absorb_once(&state->ctx[2], in2, inlen);
  mlk_shake128_absorb_once(&state->ctx[3], in3, inlen);
}

static MLK_INLINE void mlk_shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mlk_shake128x4ctx *state)
{
  mlk_shake128_squeezeblocks(out0, nblocks, &state->ctx[0]);
  mlk_shake128_squeezeblocks(out1, nblocks, &state->ctx[1]);
  mlk_shake128_squeezeblocks(out2, nblocks, &state->ctx[2]);
  mlk_shake128_squeezeblocks(out3, nblocks, &state->ctx[3]);
}

static MLK_INLINE void mlk_shake128x4_init(mlk_shake128x4ctx *state) { (void)state; }
static MLK_INLINE void mlk_shake128x4_release(mlk_shake128x4ctx *state)
{
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(state, sizeof(mlk_shake128x4ctx));
}

static MLK_INLINE void mlk_shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                    size_t outlen, uint8_t *in0, uint8_t *in1, uint8_t *in2,
                    uint8_t *in3, size_t inlen)
{
  mlk_shake256(out0, outlen, in0, inlen);
  mlk_shake256(out1, outlen, in1, inlen);
  mlk_shake256(out2, outlen, in2, inlen);
  mlk_shake256(out3, outlen, in3, inlen);
}

#endif /* MLK_FIPS202_FIPS202X4_H */