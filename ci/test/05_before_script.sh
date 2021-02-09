#!/usr/bin/env bash
#
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# Make sure default datadir does not exist and is never read by creating a dummy file
if [ "$CI_OS_NAME" == "macos" ]; then
  echo > $HOME/Library/Application\ Support/Bitcoin
else
  DOCKER_EXEC echo \> \$HOME/.bitcoin
fi

DOCKER_EXEC mkdir -p ${DEPENDS_DIR}/SDKs ${DEPENDS_DIR}/sdk-sources

OSX_SDK_BASENAME="Xcode-${XCODE_VERSION}-${XCODE_BUILD_ID}-extracted-SDK-with-libcxx-headers.tar.gz"
OSX_SDK_PATH="${DEPENDS_DIR}/sdk-sources/${OSX_SDK_BASENAME}"

if [ -n "$XCODE_VERSION" ] && [ ! -f "$OSX_SDK_PATH" ]; then
  curl --location --fail "${SDK_URL}/${OSX_SDK_BASENAME}" -o "$OSX_SDK_PATH"
fi

if [ -n "$XCODE_VERSION" ] && [ -f "$OSX_SDK_PATH" ]; then
  DOCKER_EXEC tar -C "${DEPENDS_DIR}/SDKs" -xf "$OSX_SDK_PATH"
fi
if [[ $HOST = *-mingw32 ]]; then
  DOCKER_EXEC update-alternatives --set $HOST-g++ \$\(which $HOST-g++-posix\)
fi
if [ -n "$PREVIOUS_RELEASES_TO_DOWNLOAD" ]; then
  DOCKER_EXEC test/get_previous_releases.py -b -t "$PREVIOUS_RELEASES_DIR" "${PREVIOUS_RELEASES_TO_DOWNLOAD}"
fi
