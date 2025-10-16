# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

mlkem_native = module_extension(
    implementation = lambda _: _mlkem_native_repos(),
)

def _mlkem_native_repos():
    http_archive(
        name = "mlkem_native",
        build_file = Label("//third_party/mlkem_native:BUILD.mlkem_native.bazel"),
        sha256 = "5b48421c16fbe2cd0408e98d7a66a03fd0f8d5e43d01a45ded2a24050529c9ab",
        strip_prefix = "mlkem-native-e50debc01f6399597a260c0adc3235a3debca90a",
        urls = [
            "https://github.com/pq-code-package/mlkem-native/archive/e50debc01f6399597a260c0adc3235a3debca90a.tar.gz",
        ],
    )
