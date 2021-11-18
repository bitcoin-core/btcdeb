// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <debugger/interpreter.h>
#include <debugger/script.h>

#include <tinyformat.h>

extern const CHashWriter HASHER_TAPSIGHASH;
static const CHashWriter HASHER_TAPTWEAK = TaggedHash("TapTweak");

TaprootCommitmentEnv::TaprootCommitmentEnv(const std::vector<unsigned char>& control, const std::vector<unsigned char>& program, const CScript& script, uint256* tapleaf_hash)
:   m_control(control)
,   m_program(program)
,   m_script(script)
,   m_tapleaf_hash(tapleaf_hash)
,   m_p{uint256(std::vector<unsigned char>(control.begin() + 1, control.begin() + TAPROOT_CONTROL_BASE_SIZE))}
,   m_q{uint256(program)}
,   m_applied_tweak{false} {
    btc_taproot_logf("Taproot commitment:\n");
    btc_taproot_logf("- control  = %s\n", HexStr(control).c_str());
    btc_taproot_logf("- program  = %s\n", HexStr(program).c_str());
    btc_taproot_logf("- script   = %s\n", HexStr(script).c_str());
    m_path_len = (control.size() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    btc_taproot_logf("- path len = %d\n", m_path_len);
    btc_taproot_logf("- p        = %s\n", m_p.ToString().c_str());
    btc_taproot_logf("- q        = %s\n", m_q.ToString().c_str());
    m_k = (CHashWriter(HASHER_TAPLEAF) << uint8_t(control[0] & TAPROOT_LEAF_MASK) << script).GetSHA256();
    btc_taproot_logf("- k        = %s          (tap leaf hash)\n", m_k.ToString().c_str());
    m_k_desc = strprintf("TapLeaf(0x%02x || %s)", uint8_t(control[0] & TAPROOT_LEAF_MASK), HexStr(script).c_str());
    btc_taproot_logf("  (%s)\n", m_k_desc.c_str());
    if (m_tapleaf_hash) *m_tapleaf_hash = m_k;
    m_i = 0;
}
TaprootCommitmentEnv::State TaprootCommitmentEnv::Iterate() {
    btc_taproot_logf("- looping over path (0..%d)\n", m_path_len-1);
    if (m_i < m_path_len) {
        CHashWriter ss_branch = HASHER_TAPBRANCH;
        Span<const unsigned char> node(m_control.data() + TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * m_i, TAPROOT_CONTROL_NODE_SIZE);
        if (std::lexicographical_compare(m_k.begin(), m_k.end(), node.begin(), node.end())) {
            btc_taproot_logf("  - %d: node = %02x...; taproot control node match -> k first\n", m_i, node[0]);
            m_k_desc = strprintf("TapBranch(%s || Span<%d,%zu>=%s)", m_k_desc.c_str(), TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * m_i, TAPROOT_CONTROL_NODE_SIZE, HexStr(node).c_str());
            ss_branch << m_k << node;
        } else {
            btc_taproot_logf("  - %d: node = %02x...; taproot control node mismatch -> k second\n", m_i, node[0]);
            m_k_desc = strprintf("TapBranch(Span<%d,%zu>=%s || %s)", TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * m_i, TAPROOT_CONTROL_NODE_SIZE, HexStr(node).c_str(), m_k_desc.c_str());
            ss_branch << node << m_k;
        }
        btc_taproot_logf("  (%s)\n", m_k_desc.c_str());
        m_k = ss_branch.GetSHA256();
        btc_taproot_logf("  - %d: k -> %s\n", m_i, m_k.ToString().c_str());
        ++m_i;
        return State::Processing;
    }
    // if (!m_applied_tweak) {
    //     m_k_desc = strprintf("TapTweak(internal_pubkey=%s || %s)", HexStr(MakeSpan(m_p)).c_str(), m_k_desc.c_str());
    //     m_k = (CHashWriter(HASHER_TAPTWEAK) << MakeSpan(m_p) << m_k).GetSHA256();
    //     btc_taproot_logf("- final k  = %s\n", m_k.ToString().c_str());
    //     btc_taproot_logf("  (%s)\n", m_k_desc.c_str());
    //     m_applied_tweak = true;
    //     return State::Tweaked;
    // }
    bool res = m_q.CheckTapTweak(m_p, m_k, m_control[0] & 1); // TODO: verify that CheckPayToContract -> CheckTapTweak
    btc_taproot_logf("- q.CheckTapTweak(p, k, %d) == %s\n", m_control[0] & 1, res ? "success" : "failure");
    return res ? State::Done : State::Failed;
}

std::vector<std::string> TaprootCommitmentEnv::Description() {
    std::vector<std::string> rv;
    for (size_t i = 0; i < m_path_len; ++i) {
        auto node_begin = m_control.data() + TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        rv.push_back(strprintf("Branch: %s", HexStr(Span<const unsigned char>(node_begin, TAPROOT_CONTROL_NODE_SIZE)).c_str()));
    }
    rv.push_back(strprintf("Tweak: %s", m_p.ToString().c_str()));
    rv.push_back(strprintf("CheckTapTweak"));
    return rv;
}

InterpreterEnv::InterpreterEnv(std::vector<valtype>& stack_in, const CScript& script_in, unsigned int flags_in, const BaseSignatureChecker& checker_in, SigVersion sigversion_in, ScriptError* error_in)
: ScriptExecutionEnvironment(stack_in, script_in, flags_in, checker_in)
, pc(script.begin())
, scriptIn(script_in)
, curr_op_seq(0)
, done(pc == pend)
, tce(nullptr)
{
    sigversion = sigversion_in;
    serror = error_in;

    operational = true;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > MAX_SCRIPT_SIZE) {
        set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
        operational = false;
        return;
    }
    nOpCount = 0;
    fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    // figure out if p2sh
    is_p2sh = (
        (flags & SCRIPT_VERIFY_P2SH) &&
        script.size() == 23 &&
        script[0] == OP_HASH160 &&
        script[1] == 20 &&
        script[22] == OP_EQUAL
    );
    if (is_p2sh) {
        // we have "executed" the sigscript already (in the form of pushes onto the stack),
        // so we need to copy the stack here
        p2shstack = stack_in;
    }
}

bool CastToBool(const valtype& vch);

bool StepScript(InterpreterEnv& env)
{
    // tapscript commitments go first
    if (env.tce) {
        switch (env.tce->Iterate()) {
        case TaprootCommitmentEnv::State::Failed:
            return false;
        case TaprootCommitmentEnv::State::Tweaked:
        case TaprootCommitmentEnv::State::Processing:
            ++env.curr_op_seq;
            return true;
        case TaprootCommitmentEnv::State::Done:
            ++env.curr_op_seq;
            env.execdata.m_tapleaf_hash = *env.tce->m_tapleaf_hash;
            env.execdata.m_tapleaf_hash_init = true;
            delete env.tce;
            env.tce = nullptr;
            return true;
        }
    }

    auto& pend = env.pend;
    auto& pc = env.pc;

    if (pc < pend) {
        // Store history entry
        env.stack_history.push_back(env.stack);
        env.altstack_history.push_back(env.altstack);
        env.pc_history.push_back(env.pc);
        env.nOpCount_history.push_back(env.nOpCount);

        if (!StepScript(env, pc)) {
            // undo above pushes
            env.stack_history.pop_back();
            env.altstack_history.pop_back();
            env.pc_history.pop_back();
            env.nOpCount_history.pop_back();
            return false;
        }

        // Update environment
        env.curr_op_seq++;
        return true;
    }

    auto& vfExec = env.vfExec;
    auto& script = env.script;
    auto& stack = env.stack;
    auto& is_p2sh = env.is_p2sh;
    auto& serror = env.serror;

    if (is_p2sh) {
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (CastToBool(stack.back()) == false)
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        // Additional validation for spend-to-script-hash transactions:
        if (env.script.IsPayToScriptHash()) {
            // // scriptSig must be literals-only or validation fails
            // if (!scriptSig.IsPushOnly())
            //     return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

            // Restore stack.
            is_p2sh = false;
            stack = env.p2shstack;
            // swap(stack, stackCopy);

            // stack cannot be empty here, because if it was the
            // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
            // an empty stack and the EvalScript above would return false.
            assert(!stack.empty());

            const valtype& pubKeySerialized = stack.back();
            CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
            script = pubKey2;
            popstack(stack);

            pc = env.pbegincodehash = script.begin();
            pend = script.end();
            env.curr_op_seq++;
            env.nOpCount = 0; // reset to avoid hitting limit prematurely!
            return true;
        }
        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
    }

    if (env.successor_script.size()) {
        script = env.successor_script;
        env.successor_script.clear();
        pc = env.pbegincodehash = script.begin();
        pend = script.end();
        env.curr_op_seq++;

        // figure out if p2sh
        env.is_p2sh = (
            (env.flags & SCRIPT_VERIFY_P2SH) &&
            script.size() == 23 &&
            script[0] == OP_HASH160 &&
            script[1] == 20 &&
            script[22] == OP_EQUAL
        );
        if (env.is_p2sh) {
            // we have "executed" the sigscript already (in the form of pushes onto the stack),
            // so we need to copy the stack here
            env.p2shstack = env.stack;
        }
        env.nOpCount = 0; // reset to avoid hitting limit prematurely!
        return true;
    }

    // we are at end; set done var
    env.done = true;

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

bool RewindScript(InterpreterEnv& env)
{
    if (env.stack_history.size() == 0) {
        printf("no stack history\n");
        return false;
    }
    // Rewind from history
    env.stack = env.stack_history.back();
    env.altstack = env.altstack_history.back();
    env.pc = env.pc_history.back();
    env.curr_op_seq--;
    env.nOpCount = env.nOpCount_history.back();
    // Pop
    env.stack_history.pop_back();
    env.altstack_history.pop_back();
    env.pc_history.pop_back();
    env.nOpCount_history.pop_back();
    return true;
}

bool ContinueScript(InterpreterEnv& env)
{
    while (!env.done) {
        if (!StepScript(env)) return false;
    }
    return true;
}

#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

bool StepExtended(ScriptExecutionEnvironment& env, CScript::const_iterator& pc, CScript* local_script)
{
    auto& stack = env.stack;
    auto& serror = env.serror;

    valtype vch1, vch2, vch3;
    switch (env.opcode) {
    case OP_CAT:
        // (x1 x2 -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        vch1.insert(vch1.end(), vch2.begin(), vch2.end());
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_SUBSTR:
        // (in begin size -- out)
        if (stack.size() < 3) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-3);
        vch2 = stacktop(-2);
        vch3 = stacktop(-1);

        {
            // begin
            const CScriptNum begin(vch2, env.fRequireMinimal, 2);
            if (begin < 0) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            // size
            const CScriptNum size(vch3, env.fRequireMinimal, 2);
            if (size < 0 || begin + size > vch1.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            if (begin > 0) {
                vch1.erase(vch1.begin(), vch1.begin() + begin.getint());
            }
            if (size < vch1.size()) {
                vch1.erase(vch1.begin() + size.getint(), vch1.end());
            }
        }
        popstack(stack);
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_LEFT:
    case OP_RIGHT:
        // (in size -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        {
            // size
            const CScriptNum size(vch2, env.fRequireMinimal, 2);
            if (size < 0 || size > vch1.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            if (size < vch1.size()) {
                if (env.opcode == OP_LEFT) {
                    vch1.erase(vch1.begin() + size.getint(), vch1.end());
                } else {
                    vch1.erase(vch1.begin(), vch1.end() - size.getint());
                }
            }
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_INVERT:
        // (in -- out)
        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-1);
        for (size_t i = 0; i < vch1.size(); ++i) vch1[i] = ~vch1[i];
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_AND:
    case OP_OR:
    case OP_XOR:
        // (x1 x2 -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        if (vch1.size() != vch2.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
        if (env.opcode == OP_AND) {
            for (size_t i = 0; i < vch1.size(); ++i) vch1[i] &= vch2[i];
        } else if (env.opcode == OP_OR) {
            for (size_t i = 0; i < vch1.size(); ++i) vch1[i] |= vch2[i];
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_2MUL:
        // (in -- out)
        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-1);
        {
            // multiply by 2 = left-shift one bit
            uint16_t carry = 0;
            for (size_t i = 0; i < vch1.size(); ++i) {
                uint16_t v = vch1[i];
                v = (v << 1) | carry;
                carry = v >> 8;
                vch1[i] = v & 0xff;
            }
            if (carry) vch1.push_back(carry);
        }
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_MUL:
    case OP_DIV:
    case OP_MOD:
    case OP_LSHIFT:
    case OP_RSHIFT:
        // (a b -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        {
            CScriptNum num1(vch1, env.fRequireMinimal, 5);
            CScriptNum num2(vch2, env.fRequireMinimal, 5);
            switch (env.opcode) {
            case OP_MUL: num1 = num1 * num2; break;
            case OP_DIV: num1 = num1 / num2; break;
            case OP_MOD: num1 = num1 % num2; break;
            case OP_LSHIFT: num1 = num1 << num2; break;
            case OP_RSHIFT: num1 = num1 >> num2; break;
            default: assert(0);
            }
            vch1 = num1.getvch();
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;
    default: assert(0);
    }
}
