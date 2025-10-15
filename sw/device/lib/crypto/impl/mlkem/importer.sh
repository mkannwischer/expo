#!/bin/bash

# Copyright (c) The mlkem-native project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT


# mlkem-native importer script
#
# This script imports a version of mlkem-native into OpenTitan.
#
# Usage:
#
# ```
# GITHUB_SHA={COMMIT_HASH} ./importer.sh
# ```
#

GITHUB_SHA=${GITHUB_SHA:=main}

SRC=mlkem-native
WORK=$(mktemp -d) || exit 1
echo "Working directory: $WORK"

# Remove source if they already exist
rm -rf $SRC

pushd $WORK
echo "Fetching mlkem-native ..."
git clone https://github.com/pq-code-package/mlkem-native --depth 1 --branch=$GITHUB_SHA
cd mlkem-native
GITHUB_COMMIT=$(git rev-parse HEAD)
popd

echo "Copying sources ..."
mkdir -p $SRC/src
cp $WORK/mlkem-native/mlkem/src/* $SRC/src/
cp $WORK/mlkem-native/mlkem/*.[ch] $SRC
rm $SRC/src/config.h


echo "Remove working directory ..."
rm -rf $TMP


echo "Generating META.yml file ..."
cat <<EOF > META.yml
name: mlkem-native
commit: $GITHUB_COMMIT
imported-at: $(date "+%Y-%m-%dT%H:%M:%S%z")
EOF