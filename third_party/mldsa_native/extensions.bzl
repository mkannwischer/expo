# Copyright The mldsa-native project authors
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

mldsa_native = module_extension(
    implementation = lambda _: _mldsa_native_repos(),
)

def _mldsa_native_repos():
    http_archive(
        name = "mldsa_native",
        build_file = Label("//third_party/mldsa_native:BUILD.mldsa_native.bazel"),
        sha256 = "02f22e4b4509abc1b7bc539d7a4522be950eed72551361884c939d450eb52790",
        strip_prefix = "mldsa-native-3380c330162e2a998d9b5454ca1103ddac84c2e2",
        urls = [
            "https://github.com/pq-code-package/mldsa-native/archive/3380c330162e2a998d9b5454ca1103ddac84c2e2.tar.gz",
        ],
    )
