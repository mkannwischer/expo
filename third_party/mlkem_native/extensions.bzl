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
        sha256 = "125cd25b2462e47ec41a6034469e8dc47d5c9042e0f969f40d4b63f7363fa67c",
        strip_prefix = "mlkem-native-5aaca94bd516c0a9f4d212948cd30e873d4a2956",
        urls = [
            "https://github.com/pq-code-package/mlkem-native/archive/5aaca94bd516c0a9f4d212948cd30e873d4a2956.tar.gz",
        ],
    )
