// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <debugger/interpreter.h>
#include <debugger/script.h>

InterpreterEnv::InterpreterEnv(std::vector<valtype>& stack_in, const CScript& script_in, unsigned int flags_in, const BaseSignatureChecker& checker_in, SigVersion sigversion_in, ScriptError* error_in)
: ScriptExecutionEnvironment(stack_in, script_in, flags_in, checker_in)
, pc(script.begin())
, scriptIn(script_in)
, curr_op_seq(0)
, done(pc == pend)
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
            return true;
        }
        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
    }

    if (env.successor_script.size()) {
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (CastToBool(stack.back()) == false)
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        script = env.successor_script;
        env.successor_script.clear();
        pc = env.pbegincodehash = script.begin();
        pend = script.end();
        env.curr_op_seq++;

        // figure out if p2sh
        env.is_p2sh = (
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
