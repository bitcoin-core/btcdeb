# Copyright (c) 2013-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)
EXTRA_LIBRARIES =

BITCOIN_INCLUDES=-I$(builddir)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include

LIBBITCOIN=libbitcoin.a
LIBBITCOIN_CRYPTO_BASE=crypto/libbitcoin_crypto_base.a
LIBKERL=libkerl.a
LIBSECP256K1=secp256k1/libsecp256k1.la

LIBBITCOIN_CRYPTO=$(LIBBITCOIN_CRYPTO_BASE)
if ENABLE_SSE41
LIBBITCOIN_CRYPTO_SSE41 = crypto/libbitcoin_crypto_sse41.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBBITCOIN_CRYPTO_AVX2 = crypto/libbitcoin_crypto_avx2.a
LIBBITCOIN_CRYPTO += $(LIBBITCOIN_CRYPTO_AVX2)
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN) \
  $(LIBKERL)

# lib_LTLIBRARIES = $(LIBBITCOIN)

bin_PROGRAMS = btcdeb btcc vanitygen test-btcdeb
noinst_PROGRAMS =

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
	amount.h \
	base58.h \
	bech32.h \
	compat.h \
	compat/byteswap.h \
	compat/endian.h \
	debugger/interpreter.h \
	debugger/script.h
	hash.h \
	script/interpreter.h \
	merkle.h \
	policy/policy.h \
	prevector.h \
	primitives/transaction.h \
	pubkey.h \
	script/script.h \
	script/script_error.h \
	serialize.h \
	span.h \
	streams.h \
	support/allocators/secure.h \
	support/allocators/zeroafterfree.h \
	support/cleanse.h \
	support/lockedpool.h \
	tinyformat.h \
	uint256.h \
	utilstrencodings.h \
	value.h

# crypto primitives library
crypto_libbitcoin_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_base_a_SOURCES = \
  crypto/common.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

if USE_ASM
crypto_libbitcoin_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libbitcoin_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libbitcoin_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libbitcoin_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libbitcoin_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libbitcoin_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libbitcoin_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libbitcoin_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp


# bitcoin: shared between all the tools
libbitcoin_a_LIBADD = $(LIBSECP256K1)
libbitcoin_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_a_CXXFLAGS = $(AM_CXXFLAGS)
libbitcoin_a_SOURCES = \
	$(crypto_libbitcoin_crypto_base_a_SOURCES) \
	base58.cpp \
	bech32.cpp \
	debugger/hash.cpp \
	debugger/interpreter.cpp \
	debugger/script.cpp \
	hash.cpp \
	merkle.cpp \
	primitives/transaction.cpp \
	pubkey.cpp \
	script/interpreter.cpp \
	script/script.cpp \
	script/script_error.cpp \
	support/cleanse.cpp \
	support/lockedpool.cpp \
	uint256.cpp \
	utilstrencodings.cpp \
	value.cpp \
    $(BITCOIN_CORE_H)

# kerl library #
libkerl_a_CPPFLAGS = $(AM_CPPFLAGS) -Ikerl
libkerl_a_CFLAGS = -std=gnu99
libkerl_a_SOURCES = kerl/kerl.c kerl/kerl.h

# btcdeb binary #
btcdeb_SOURCES = \
	instance.h \
	instance.cpp \
	btcdeb.cpp \
	cliargs.h
btcdeb_CPPFLAGS = $(AM_CPPFLAGS)
btcdeb_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
btcdeb_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_AP_LDFLAGS)

btcdeb_LDADD = \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBBITCOIN) \
	$(LIBSECP256K1) \
	$(LIBKERL)

# btcc binary #
btcc_SOURCES = \
	btcc.cpp
btcc_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
btcc_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

btcc_LDADD = \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBBITCOIN)

# vanitygen binary #
vanitygen_SOURCES = \
	vanitygen.cpp \
	cliargs.h
vanitygen_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
vanitygen_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
vanitygen_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_AP_LDFLAGS)

vanitygen_LDADD = \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBBITCOIN) \
	$(LIBSECP256K1)

# test-btcdeb binary #
test_btcdeb_SOURCES = \
	instance.h \
	instance.cpp \
	test/catch.hpp \
	test/signing.cpp \
	test/test-btcdeb.cpp \
	test/value.cpp
test_btcdeb_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
test_btcdeb_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
test_btcdeb_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_AP_LDFLAGS)

test_btcdeb_LDADD = \
	$(LIBBITCOIN_CRYPTO) \
	$(LIBBITCOIN) \
	$(LIBKERL) \
	$(LIBSECP256K1)

clean-local:
	-rm -f config.h $(LIBBITCOIN) $(LIBKERL) $(LIBSECP256K1)

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

