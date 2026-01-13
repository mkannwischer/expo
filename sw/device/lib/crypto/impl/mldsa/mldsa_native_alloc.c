// Copyright The mldsa-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/impl/mldsa/mldsa_native_alloc.h"

void *mld_alloc(mld_alloc_ctx_t *ctx, size_t size_bytes) {
  size_t size_words = MLD_ALIGN_UP(size_bytes) / sizeof(uint32_t);

  if (ctx->offset_words + size_words > ctx->size_words) {
    return NULL;  // Out of space
  }

  void *ptr = (void *)(ctx->base + ctx->offset_words);
  ctx->offset_words += size_words;
  return ptr;
}

void mld_free(void *ptr, mld_alloc_ctx_t *ctx, size_t size_bytes) {
  if (ptr == NULL) {
    return;  // No-op if NULL
  }

  size_t size_words = MLD_ALIGN_UP(size_bytes) / sizeof(uint32_t);
  ctx->offset_words -= size_words;
}
