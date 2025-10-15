# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "mlkem_native",
    srcs = ["mlkem_native_monobuild.c"],
    hdrs = [
    "mlkem_native_monobuild.h",
    "config.h",
    "fips202_glue.h",
    "fips202x4_glue.h",
    "mlkem-native/mlkem_native.c",
    "mlkem-native/mlkem_native.h",
    "mlkem-native/src/cbmc.h",
    "mlkem-native/src/common.h",
    "mlkem-native/src/randombytes.h",
    "mlkem-native/src/debug.h",
    "mlkem-native/src/debug.c",
    "mlkem-native/src/compress.h",
    "mlkem-native/src/compress.c",
    "mlkem-native/src/indcpa.c",
    "mlkem-native/src/indcpa.h",
    "mlkem-native/src/kem.c",
    "mlkem-native/src/kem.h",
    "mlkem-native/src/params.h",
    "mlkem-native/src/poly_k.c",
    "mlkem-native/src/poly_k.h",
    "mlkem-native/src/poly.c",
    "mlkem-native/src/poly.h",
    "mlkem-native/src/zetas.inc",
    "mlkem-native/src/sampling.c",
    "mlkem-native/src/sampling.h",
    "mlkem-native/src/symmetric.h",
    "mlkem-native/src/sys.h",
    "mlkem-native/src/verify.c",
    "mlkem-native/src/verify.h",
    ],
    includes = ["."],
    deps = [
        "//sw/device/lib/crypto/impl:sha3",
    ],
    copts = [
        '-DMLK_CONFIG_FILE=\\"config.h\\"',
        "-Wno-implicit-int-conversion",
        "-Wno-sign-conversion",
    ],
)
