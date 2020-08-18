#!/usr/bin/env bash
#
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

if [[ $HOST = *-mingw32 ]]; then
  # Generate all binaries, so that they can be wrapped
  DOCKER_EXEC make $MAKEJOBS -C secp256k1 VERBOSE=1
  DOCKER_EXEC "${BASE_ROOT_DIR}/ci/test/wrap-wine.sh"
fi

if [ -n "$QEMU_USER_CMD" ]; then
  # Generate all binaries, so that they can be wrapped
  DOCKER_EXEC make $MAKEJOBS -C secp256k1 VERBOSE=1
  DOCKER_EXEC "${BASE_ROOT_DIR}/ci/test/wrap-qemu.sh"
fi

if [ -n "$USE_VALGRIND" ]; then
  DOCKER_EXEC "${BASE_ROOT_DIR}/ci/test/wrap-valgrind.sh"
fi

if [ "$RUN_UNIT_TESTS" = "true" ]; then
  DOCKER_EXEC ${TEST_RUNNER_ENV} "cp -r ${BASE_ROOT_DIR}/doc ${BASE_OUTDIR}"
  DOCKER_EXEC ${TEST_RUNNER_ENV} "echo \"base outdir = ${BASE_OUTDIR}\""
  DOCKER_EXEC ${TEST_RUNNER_ENV} "LD_LIBRARY_PATH=$DEPENDS_DIR/$HOST/lib cd ${BASE_OUTDIR} && pwd && ls -l && ls -l bin && bin/test-btcdeb"
fi
