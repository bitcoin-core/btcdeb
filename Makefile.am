# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

AM_LDFLAGS = $(LIBTOOL_LDFLAGS)
EXTRA_LIBRARIES =

BITCOIN_INCLUDES=-I$(builddir)

LIBBITCOIN=libbitcoin.a
LIBKERL=libkerl.a

EXTRA_LIBRARIES += \
  $(LIBBITCOIN) \
  $(LIBKERL)

# lib_LTLIBRARIES = $(LIBBITCOIN)

bin_PROGRAMS = btcdeb btcc
noinst_PROGRAMS =

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
	crypto/common.h      crypto/hmac_sha512.h crypto/ripemd160.h   crypto/sha1.h        crypto/sha256.h      crypto/sha512.h \
	compat/byteswap.h compat/endian.h \
	hash.h             interpreter.h      prevector.h        script.h           script_error.h     serialize.h        \
	tinyformat.h       uint256.h          utilstrencodings.h

# bitcoin: shared between btcdeb and btcc
libbitcoin_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_a_CXXFLAGS = $(AM_CXXFLAGS)
libbitcoin_a_SOURCES = \
	crypto/hmac_sha512.cpp crypto/ripemd160.cpp   crypto/sha1.cpp        crypto/sha256.cpp      crypto/sha512.cpp \
	hash.cpp             interpreter.cpp      script.cpp           script_error.cpp     uint256.cpp          utilstrencodings.cpp \
    $(BITCOIN_CORE_H)

# kerl library #
libkerl_a_CPPFLAGS = $(AM_CPPFLAGS) -Ikerl
libkerl_a_SOURCES = kerl/kerl.c kerl/kerl.h

# btcdeb binary #
btcdeb_SOURCES = btcdeb.cpp
btcdeb_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
btcdeb_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
btcdeb_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_AP_LDFLAGS) -lreadline

btcdeb_LDADD = \
	$(LIBBITCOIN) \
	$(LIBKERL)

# btcc binary #
btcc_SOURCES = btcc.cpp
btcc_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
btcc_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

btcc_LDADD = \
	$(LIBBITCOIN)

clean-local:
	-rm -f config.h

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

