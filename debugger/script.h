// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BTCDEB_SCRIPT_H
#define BITCOIN_BTCDEB_SCRIPT_H

#include <script/script.h>

typedef void (*btc_logf_t) (const char *fmt...);
extern btc_logf_t btc_logf, btc_sighash_logf, btc_sign_logf, btc_segwit_logf;
extern bool btcdeb_verbose;
void btc_logf_dummy(const char* fmt...);
void btc_logf_stderr(const char* fmt...);
inline bool btc_enabled(btc_logf_t logger) { return logger != btc_logf_dummy; }

opcodetype GetOpCode(const char* name);
void GetStackFeatures(opcodetype opcode, size_t& spawns, size_t& slays);

#endif // BITCOIN_BTCDEB_SCRIPT_H
