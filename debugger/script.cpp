// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <debugger/script.h>

// #include <util/strencodings.h>
#include <cstdarg>

void btc_logf_dummy(const char* fmt...) {}
void btc_logf_stderr(const char* fmt...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
btc_logf_t btc_logf = btc_logf_stderr;
btc_logf_t btc_sighash_logf = btc_logf_dummy;
btc_logf_t btc_sign_logf = btc_logf_dummy;
btc_logf_t btc_segwit_logf = btc_logf_dummy;
btc_logf_t btc_taproot_logf = btc_logf_dummy;

opcodetype GetOpCode(const char* name)
{
    // trim out "OP_" as people tend to skip those
    if (name[0] == 'O' && name[1] == 'P' && name[2] == '_') {
        name = &name[3];
    }
    // push value
    #define c(v) if (!strcmp(#v, name)) return OP_##v
    c(0);
    c(FALSE);
    c(PUSHDATA1);
    c(PUSHDATA2);
    c(PUSHDATA4);
    c(1NEGATE);
    c(RESERVED);
    c(1);
    c(TRUE);
    c(2);
    c(3);
    c(4);
    c(5);
    c(6);
    c(7);
    c(8);
    c(9);
    c(10);
    c(11);
    c(12);
    c(13);
    c(14);
    c(15);
    c(16);

    // control
    c(NOP);
    c(VER);
    c(IF);
    c(NOTIF);
    c(VERIF);
    c(VERNOTIF);
    c(ELSE);
    c(ENDIF);
    c(VERIFY);
    c(RETURN);

    // stack ops
    c(TOALTSTACK);
    c(FROMALTSTACK);
    c(2DROP);
    c(2DUP);
    c(3DUP);
    c(2OVER);
    c(2ROT);
    c(2SWAP);
    c(IFDUP);
    c(DEPTH);
    c(DROP);
    c(DUP);
    c(NIP);
    c(OVER);
    c(PICK);
    c(ROLL);
    c(ROT);
    c(SWAP);
    c(TUCK);

    // splice ops
    c(CAT);
    c(SUBSTR);
    c(LEFT);
    c(RIGHT);
    c(SIZE);

    // bit logic
    c(INVERT);
    c(AND);
    c(OR);
    c(XOR);
    c(EQUAL);
    c(EQUALVERIFY);
    c(RESERVED1);
    c(RESERVED2);

    // numeric
    c(1ADD);
    c(1SUB);
    c(2MUL);
    c(2DIV);
    c(NEGATE);
    c(ABS);
    c(NOT);
    c(0NOTEQUAL);
    c(ADD);
    c(SUB);
    c(MUL);
    c(DIV);
    c(MOD);
    c(LSHIFT);
    c(RSHIFT);
    c(BOOLAND);
    c(BOOLOR);
    c(NUMEQUAL);
    c(NUMEQUALVERIFY);
    c(NUMNOTEQUAL);
    c(LESSTHAN);
    c(GREATERTHAN);
    c(LESSTHANOREQUAL);
    c(GREATERTHANOREQUAL);
    c(MIN);
    c(MAX);
    c(WITHIN);

    // crypto
    c(RIPEMD160);
    c(SHA1);
    c(SHA256);
    c(HASH160);
    c(HASH256);
    c(CODESEPARATOR);
    c(CHECKSIG);
    c(CHECKSIGVERIFY);
    c(CHECKMULTISIG);
    c(CHECKMULTISIGVERIFY);

    // expansion
    c(NOP1);
    c(CHECKLOCKTIMEVERIFY);
    c(CHECKSEQUENCEVERIFY);
    c(NOP4);
    c(NOP5);
    c(NOP6);
    c(NOP7);
    c(NOP8);
    c(NOP9);
    c(NOP10);

    return OP_INVALIDOPCODE;
}

void GetStackFeatures(opcodetype opcode, size_t& spawns, size_t& slays)
{
    #define _(spawns_out, slays_out) spawns = spawns_out; slays = slays_out; return
    switch (opcode)
    {
    // control
    case OP_NOP                    :
    case OP_ELSE                   :
    case OP_ENDIF                  : _(0,0);

    case OP_VER                    : // ?? this seems to be not used
    case OP_IF                     :
    case OP_NOTIF                  :
    case OP_VERIF                  :
    case OP_VERNOTIF               :
    case OP_VERIFY                 :
    case OP_RETURN                 : _(0, 1);

    // stack ops
    case OP_TOALTSTACK             : _(0, 1);
    case OP_FROMALTSTACK           : _(1, 0);
    case OP_2DROP                  : _(0, 2);
    case OP_2DUP                   : _(4, 2);
    case OP_3DUP                   : _(6, 3);
    case OP_2OVER                  : _(6, 4);
    case OP_2ROT                   : _(6, 6);
    case OP_2SWAP                  : _(4, 4);
    case OP_IFDUP                  : _(2, 2);
    case OP_DEPTH                  : _(1, 0);
    case OP_DROP                   : _(0, 1);
    case OP_DUP                    : _(2, 1);
    case OP_NIP                    : _(1, 2);
    case OP_OVER                   : _(3, 2);
    case OP_PICK                   :
    case OP_ROLL                   : _(0, 2);
    case OP_ROT                    : _(3, 3);
    case OP_SWAP                   : _(2, 2);
    case OP_TUCK                   : _(3, 2);

    // splice ops
    case OP_CAT                    :
    case OP_SUBSTR                 :
    case OP_LEFT                   :
    case OP_RIGHT                  : _(0, 0); // disabled; if enabled, must fix
    case OP_SIZE                   : _(2, 1);

    // bit logic
    case OP_INVERT                 :
    case OP_AND                    :
    case OP_OR                     :
    case OP_XOR                    : _(0, 0); // disabled
    case OP_EQUAL                  : _(1, 2);
    case OP_EQUALVERIFY            : _(0, 2);
    case OP_RESERVED1              :
    case OP_RESERVED2              : _(0, 0);

    // numeric
    case OP_1ADD                   :
    case OP_1SUB                   :
    case OP_2MUL                   :
    case OP_2DIV                   :
    case OP_NEGATE                 :
    case OP_ABS                    :
    case OP_NOT                    :
    case OP_0NOTEQUAL              : _(1, 1);
    case OP_ADD                    :
    case OP_SUB                    :
    case OP_MUL                    :
    case OP_DIV                    :
    case OP_BOOLAND                :
    case OP_BOOLOR                 :
    case OP_NUMEQUAL               :
    case OP_NUMNOTEQUAL            :
    case OP_LESSTHAN               :
    case OP_GREATERTHAN            :
    case OP_LESSTHANOREQUAL        :
    case OP_GREATERTHANOREQUAL     :
    case OP_MIN                    :
    case OP_MAX                    : _(1, 2);
    case OP_NUMEQUALVERIFY         : _(0, 2);
    case OP_MOD                    :
    case OP_LSHIFT                 :
    case OP_RSHIFT                 : _(0, 0);
    case OP_WITHIN                 : _(1, 3);

    // crypto
    case OP_RIPEMD160              :
    case OP_SHA1                   :
    case OP_SHA256                 :
    case OP_HASH160                :
    case OP_HASH256                : _(1, 1);
    case OP_CODESEPARATOR          : _(0, 0);
    case OP_CHECKSIG               : _(1, 2);
    case OP_CHECKSIGVERIFY         : _(0, 2);
    case OP_CHECKMULTISIG          : _(1, 3); // this depends on k-of-n's k and n
    case OP_CHECKMULTISIGVERIFY    : _(0, 3); // -'-

    // expansion
    case OP_NOP1                   : _(0, 0);
    case OP_CHECKLOCKTIMEVERIFY    : _(1, 1);
    case OP_CHECKSEQUENCEVERIFY    : _(1, 1);
    case OP_NOP4                   :
    case OP_NOP5                   :
    case OP_NOP6                   :
    case OP_NOP7                   :
    case OP_NOP8                   :
    case OP_NOP9                   :
    case OP_NOP10                  : _(0, 0);

    default:
        _(1, 0); // default is all the push commands
    }
    #undef _
}
