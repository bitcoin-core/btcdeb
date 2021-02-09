// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BTCDEB_INTERPRETER_H
#define BITCOIN_BTCDEB_INTERPRETER_H

#include <script/interpreter.h>
#include <util/strencodings.h> // HexStr
#include <pubkey.h> // XOnlyPubKey
#include <vector>
#include <string>

template <typename T, typename T2> static inline void print_vec(const T& v, T2 fun) {
    for (unsigned char c : v) fun("%02x", c);
}

static inline std::string hashtype_str(int h) {
    char buf[100];
    char* pbuf = buf;
    if ((h & 0x1f) == SIGHASH_ALL) pbuf += sprintf(pbuf, " SIGHASH_ALL");
    if ((h & 0x1f) == SIGHASH_NONE) pbuf += sprintf(pbuf, " SIGHASH_NONE");
    if ((h & 0x1f) == SIGHASH_SINGLE) pbuf += sprintf(pbuf, " SIGHASH_SINGLE");
    if (h & SIGHASH_ANYONECANPAY) pbuf += sprintf(pbuf, " SIGHASH_ANYONECANPAY");
    return &buf[1];
}

typedef std::vector<unsigned char> valtype;
typedef std::vector<valtype> stack_type;

inline bool set_success(ScriptError* ret)
{
    if (ret)
        *ret = SCRIPT_ERR_OK;
    return true;
}

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}

static inline void _popstack(std::vector<valtype>& stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack(): stack empty");
    stack.pop_back();
}

#define popstack(stack) do { btc_logf("\t\t<> POP  " #stack "\n"); _popstack(stack); } while (0)
#define pushstack(stack, v) do { stack.push_back(v); btc_logf("\t\t<> PUSH " #stack " %s\n", HexStr(stack.at(stack.size()-1)).c_str()); } while (0)

struct TaprootCommitmentEnv {
    enum class State : uint8_t {
        Processing,
        Failed,
        Tweaked,
        Done,
    };
    const std::vector<unsigned char> m_control;
    const std::vector<unsigned char> m_program;
    const CScript m_script;
    uint256* m_tapleaf_hash;
    int m_path_len;
    XOnlyPubKey m_p;
    XOnlyPubKey m_q;
    uint256 m_k;
    std::string m_k_desc;
    int m_i;
    TaprootCommitmentEnv(const std::vector<unsigned char>& control, const std::vector<unsigned char>& program, const CScript& script, uint256* tapleaf_hash);
    State Iterate();
    std::vector<std::string> Description();
    bool m_applied_tweak;
};

struct InterpreterEnv : public ScriptExecutionEnvironment {
    CScript::const_iterator pc;
    std::vector<stack_type> stack_history;
    std::vector<stack_type> altstack_history;
    std::vector<CScript::const_iterator> pc_history;
    std::vector<int> nOpCount_history;
    std::vector<CScript> script_history;
    const CScript& scriptIn;
    int curr_op_seq;
    bool fRequireMinimal;
    bool operational;
    bool done;
    InterpreterEnv(stack_type& stack_in, const CScript& script_in, unsigned int flags_in, const BaseSignatureChecker& checker_in, SigVersion sigversion_in, ScriptError* error_in = nullptr);

    // P2SH support
    bool is_p2sh;
    stack_type p2shstack;

    // Executed sigScript support (archaeology)
    CScript successor_script;

    // Taproot/tapscript support
    TaprootCommitmentEnv* tce;
};

bool StepScript(InterpreterEnv& env);
bool ContinueScript(InterpreterEnv& env);
bool RewindScript(InterpreterEnv& env);

#endif // BITCOIN_BTCDEB_INTERPRETER_H
