#include <script/interpreter.h>
#include <utilstrencodings.h>
#include <policy/policy.h>
#include <streams.h>
#include <pubkey.h>
#include <value.h>
#include <vector>

#include <instance.h>

CTransactionRef parse_tx(const char* p) {
    std::vector<unsigned char> txData = ParseHex(p);
    if (txData.size() != (strlen(p) >> 1)) {
        fprintf(stderr, "failed to parse tx hex string\n");
        return nullptr;
    }
    CDataStream ss(txData, SER_DISK, 0);
    CMutableTransaction mtx;
    UnserializeTransaction(mtx, ss);
    CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
    return tx;
}

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
    tx = parse_tx(p);
    if (!tx) return false;
    while (amounts.size() < tx->vin.size()) amounts.push_back(0);
    if (tx->vin[0].scriptSig.size() == 0) sigver = SigVersion::WITNESS_V0;
    return true;
}

bool Instance::parse_input_transaction(const char* txdata) {
    txin = parse_tx(txdata);
    if (!txin) return false;
    if (tx) {
        // figure out index from tx vin
        const uint256& txin_hash = txin->GetHash();
        int64_t i = 0;
        for (const auto& input : tx->vin) {
            if (input.prevout.hash == txin_hash) {
                txin_index = i;
                txin_vout_index = input.prevout.n;
                break;
            }
            i++;
        }
        if (txin_index == -1) {
            fprintf(stderr, "error: the input transaction %s is not found in any of the inputs for the provided transaction %s\n", txin_hash.ToString().c_str(), tx->GetHash().ToString().c_str());
            return false;
        }
    }
    return true;
}

bool Instance::parse_script(const char* script_str) {
    std::vector<unsigned char> scriptData = Value(script_str).data_value();
    script = CScript(scriptData.begin(), scriptData.end());
    return script.HasValidOps();
}

bool Instance::parse_script(const std::vector<uint8_t>& script_data) {
    script = CScript(script_data.begin(), script_data.end());
    return script.HasValidOps();
}

void Instance::parse_stack_args(const std::vector<const char*> args) {
    for (auto& v : args) {
        stack.push_back(Value(v).data_value());
    }
}

void Instance::parse_stack_args(size_t argc, char* const* argv, size_t starting_index) {
    for (int i = starting_index; i < argc; i++) {
        stack.push_back(Value(argv[i]).data_value());
    }
}

bool Instance::setup_environment(unsigned int flags) {
    if (tx) {
        checker = new TransactionSignatureChecker(tx.get(), txin_index, amounts[0]);
    } else {
        checker = new BaseSignatureChecker();
    }
    
    env = new InterpreterEnv(stack, script, flags, *checker, sigver, &error);
    env->successor_script = successor_script;

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

bool Instance::eval(const size_t argc, char* const* argv) {
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
    CScriptIter it = script.begin();
    while (it != script.end()) {
        if (!StepScript(*env, it, &script)) {
            fprintf(stderr, "Error: %s\n", ScriptErrorString(*env->serror));
            return false;
        }
    }
    return true;
}
