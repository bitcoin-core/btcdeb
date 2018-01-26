#include <interpreter.h>
#include <utilstrencodings.h>
#include <policy/policy.h>
#include <streams.h>
#include <pubkey.h>
#include <value.h>
#include <vector>

#include <instance.h>

bool Instance::parse_transaction(const char* txdata, bool parse_amounts) {
    // parse until we run out of amounts, if requested
    const char* p = txdata;
    if (parse_amounts) {
        while (1) {
            const char* c = p;
            while (*c && *c != ',' && *c != ':') ++c;
            if (!*c) {
                if (amounts.size() == 0) {
                    // no amounts provided
                    break;
                }
                fprintf(stderr, "error: tx hex missing from input\n");
                return false;
            }
            char* s = strndup(p, c-p);
            std::string ss = s;
            free(s);
            CAmount a;
            if (!ParseFixedPoint(ss, 8, &a)) {
                fprintf(stderr, "failed to parse amount: %s\n", ss.c_str());
                return false;
            }
            amounts.push_back(a);
            p = c + 1;
            if (*c == ':') break;
        }
    }
    std::vector<unsigned char> txData = ParseHex(p);
    if (txData.size() != (strlen(p) >> 1)) {
        fprintf(stderr, "failed to parse tx hex string\n");
        return false;
    }
    CDataStream ss(txData, SER_DISK, 0);
    CMutableTransaction mtx;
    UnserializeTransaction(mtx, ss);
    tx = MakeTransactionRef(CTransaction(mtx));
    while (amounts.size() < tx->vin.size()) amounts.push_back(0);
    if (tx->vin[0].scriptSig.size() == 0) sigver = SIGVERSION_WITNESS_V0;
    return true;
}

bool Instance::parse_script(const char* script_str) {
    std::vector<unsigned char> scriptData = Value(script_str).data_value();
    script = CScript(scriptData.begin(), scriptData.end());
    return script.HasValidOps();
}

void Instance::parse_stack_args(size_t argc, const char** argv, size_t starting_index) {
    for (int i = starting_index; i < argc; i++) {
        stack.push_back(Value(argv[i]).data_value());
    }
}

bool Instance::setup_environment() {
    if (tx) {
        checker = new TransactionSignatureChecker(tx.get(), 0, amounts[0]);
    } else {
        checker = new BaseSignatureChecker();
    }
    
    env = new InterpreterEnv(stack, script, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_MERKLEBRANCHVERIFY, *checker, sigver, &error);

    return env->operational;
}

bool Instance::at_end() { return env->done; }
bool Instance::at_start() { return env->pc == env->script.begin(); }
const char* Instance::error_string() { return ScriptErrorString(*env->serror); }

bool Instance::step(size_t steps) {
    while (steps > 0) {
        if (env->done) return false;
        if (!StepScript(*env)) return false;
        steps--;
    }
    return true;
}

bool Instance::rewind() {
    if (env->pc == env->script.begin()) {
        return false;
    }
    if (env->done) {
        env->done = false;
    }
    return RewindScript(*env);
}

bool Instance::eval(const size_t argc, const char** argv) {
    if (argc < 1) return false;
    CScript script;
    for (int i = 0; i < argc; i++) {
        const char* v = argv[i];
        const size_t vlen = strlen(v);
        // empty strings are ignored
        if (!v[0]) continue;
        // number?
        int n = atoi(v);
        if (n != 0) {
            // verify
            char buf[vlen + 1];
            sprintf(buf, "%d", n);
            if (!strcmp(buf, v)) {
                // verified; can it be a hexstring too?
                if (!(vlen & 1)) {
                    std::vector<unsigned char> pushData(ParseHex(v));
                    if (pushData.size() == (vlen >> 1)) {
                        // it can; warn about using 0x for hex
                        if (VALUE_WARN) btc_logf("warning: ambiguous input %s is interpreted as a numeric value; use 0x%s to force into hexadecimal interpretation\n", v, v);
                    }
                }
                // can it be an opcode too?
                if (n < 16) {
                    if (VALUE_WARN) btc_logf("warning: ambiguous input %s is interpreted as a numeric value (%s), not as an opcode (OP_%s). Use OP_%s to force into op code interpretation\n", v, v, v, v);
                }
                
                script << (int64_t)n;
                continue;
            }
        }
        // hex string?
        if (!(vlen & 1)) {
            std::vector<unsigned char> pushData(ParseHex(v));
            if (pushData.size() == (vlen >> 1)) {
                script << pushData;
                continue;
            }
        }
        opcodetype opc = GetOpCode(v);
        if (opc != OP_INVALIDOPCODE) {
            script << opc;
            continue;
        }
        fprintf(stderr, "error: invalid opcode %s\n", v);
        return false;
    }
    CScript::const_iterator it = script.begin();
    while (it != script.end()) {
        if (!ExecIterator(*env, script, it, false)) {
            fprintf(stderr, "Error: %s\n", ScriptErrorString(*env->serror));
            return false;
        }
    }
    return true;
}
