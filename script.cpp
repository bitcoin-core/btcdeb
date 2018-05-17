// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script.h>
#include <utilstrencodings.h>
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

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_CHECKLOCKTIMEVERIFY    : return "OP_CHECKLOCKTIMEVERIFY";
    case OP_CHECKSEQUENCEVERIFY    : return "OP_CHECKSEQUENCEVERIFY";
    case OP_MERKLEBRANCHVERIFY     : return "OP_MERKLEBRANCHVERIFY";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLINTEGER/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

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
    c(MERKLEBRANCHVERIFY);
    c(NOP5);
    c(NOP6);
    c(NOP7);
    c(NOP8);
    c(NOP9);
    c(NOP10);

    // template matching params
    c(SMALLINTEGER);
    c(PUBKEYS);
    c(PUBKEYHASH);
    c(PUBKEY);

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
    case OP_MERKLEBRANCHVERIFY     : _(3, 3);
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

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += MAX_PUBKEYS_PER_MULTISIG;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    std::vector<unsigned char> vData;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, vData))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(vData.begin(), vData.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
}

bool CScript::IsPayToWitnessScriptHash() const
{
    // Extra-fast test for pay-to-witness-script-hash CScripts:
    return (this->size() == 34 &&
            (*this)[0] == OP_0 &&
            (*this)[1] == 0x20);
}

// A witness program is any valid CScript that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes.
bool CScript::IsWitnessProgram(int& version, std::vector<unsigned char>& program) const
{
    if (this->size() < 4 || this->size() > 42) {
        return false;
    }
    if ((*this)[0] != OP_0 && ((*this)[0] < OP_1 || (*this)[0] > OP_16)) {
        return false;
    }
    if ((size_t)((*this)[1] + 2) == this->size()) {
        version = DecodeOP_N((opcodetype)(*this)[0]);
        program = std::vector<unsigned char>(this->begin() + 2, this->end());
        return true;
    }
    return false;
}

bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());
}

// std::string CScriptWitness::ToString() const
// {
//     std::string ret = "CScriptWitness(";
//     for (unsigned int i = 0; i < stack.size(); i++) {
//         if (i) {
//             ret += ", ";
//         }
//         ret += HexStr(stack[i]);
//     }
//     return ret + ")";
// }

bool CScript::HasValidOps() const
{
    CScript::const_iterator it = begin();
    while (it < end()) {
        opcodetype opcode;
        std::vector<unsigned char> item;
        if (!GetOp(it, opcode, item) || opcode > MAX_OPCODE || item.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            return false;
        }
    }
    return true;
}

std::string CScriptWitness::ToString() const
{
    std::string ret = "CScriptWitness(";
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (i) {
            ret += ", ";
        }
        ret += HexStr(stack[i]);
    }
    return ret + ")";
}
