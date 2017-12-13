# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: deploy FORCE

export PYTHONPATH

BTCDEB_BIN=$(top_builddir)/$(BTCDEB_NAME)$(EXEEXT)
BTCC_BIN=$(top_builddir)/$(BTCC_NAME)$(EXEEXT)

empty :=
space := $(empty) $(empty)

$(BTCDEB_BIN): kerl/kerl.o btcdeb.cpp bitcoin
	$(MAKE) -I. btcdeb.cpp kerl/kerl.o *.o crypto/*.o -o $(BTCDEB_BIN) -lreadline

$(BTCC_BIN): btcc.cpp bitcoin
	$(MAKE) -I. btcc.cpp *.o crypto/*.o -o $(BTCC_BIN)

kerl/kerl.o: kerl/kerl.h kerl/kerl.c
	gcc -c kerl/kerl.c -o kerl/kerl.o

bitcoin: hash.o interpreter.o script.o script_error.o uint256.o utilstrencodings.o crypto

crypto: crypto/hmac_sha512.o crypto/ripemd160.o crypto/sha1.o crypto/sha256.o crypto/sha512.o

%.o: %.cpp %.h
	$(MAKE) -I. -c -o $@ $<

clean-local:
	rm -f *.o crypto/*.o kerl/kerl.o btcdeb btcc

dist_noinst_SCRIPTS = autogen.sh
