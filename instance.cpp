#include <script/interpreter.h>
#include <util/strencodings.h>
#include <policy/policy.h>
#include <streams.h>
#include <pubkey.h>
#include <value.h>
#include <vector>
#include <miniscript/compiler.h>

#include <instance.h>

CTransactionRef parse_tx(const char* p) {
    std::vector<unsigned char> txData;
    if (!TryHex(p, txData)) {
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
    if (tx->HasWitness()) sigver = SigVersion::WITNESS_V0;
    return true;
}

bool Instance::parse_input_transaction(const char* txdata, int select_index) {
    txin = parse_tx(txdata);
    if (!txin) return false;
    if (tx) {
        const uint256& txin_hash = txin->GetHash();
        if (select_index > -1) {
            // verify index is valid
            if (select_index >= tx->vin.size()) {
                fprintf(stderr, "error: the selected index %d is out of bounds (must be less than %zu, the number of inputs in the transaction)\n", select_index, tx->vin.size());
                return false;
            }
            if (txin_hash != tx->vin[select_index].prevout.hash) {
                fprintf(stderr, "error: the selected index (%d) of the transaction refers to txid %s, but the input transaction has txid %s\n", select_index, tx->vin[select_index].prevout.hash.ToString().c_str(), txin_hash.ToString().c_str());
                return false;
            }
            tx_internal_vin_index_of_txin = select_index;
            txin_vout_index_spent_by_tx = tx->vin[select_index].prevout.n;
        } else {
            // figure out index from tx vin
            int64_t i = 0;
            for (const auto& input : tx->vin) {
                if (input.prevout.hash == txin_hash) {
                    tx_internal_vin_index_of_txin = i;
                    txin_vout_index_spent_by_tx = input.prevout.n;
                    break;
                }
                i++;
            }
            if (tx_internal_vin_index_of_txin == -1) {
                fprintf(stderr, "error: the input transaction %s is not found in any of the inputs for the provided transaction %s\n", txin_hash.ToString().c_str(), tx->GetHash().ToString().c_str());
                return false;
            }
        }
    }
    return true;
}

bool Instance::parse_script(const char* script_str) {
    std::vector<unsigned char> scriptData = Value(script_str).data_value();
    script = CScript(scriptData.begin(), scriptData.end());
    for (const auto& keymap : COMPILER_CTX.keymap) {
        auto cs = keymap.first.c_str();
        auto key = Value(std::vector<uint8_t>(keymap.second.begin(), keymap.second.end())).data;
        auto sig = Value((std::string("sig:") + keymap.first).c_str()).data_value();
        pretend_valid_map[sig] = key;
        pretend_valid_pubkeys.insert(key);
        printf("info: provide sig:%s as signature for %s [%s=%s]\n", cs, cs, HexStr(sig).c_str(), HexStr(key).c_str());
    }
    try {
        msenv = new MSEnv(script, true);
    } catch (const std::exception& ex) {
        printf("miniscript failed to parse script; miniscript support disabled\n");
        msenv = nullptr;
    }
    return script.HasValidOps();
}

bool Instance::parse_script(const std::vector<uint8_t>& script_data) {
    script = CScript(script_data.begin(), script_data.end());
    return script.HasValidOps();
}

bool Instance::parse_pretend_valid_expr(const char* expr) {
    const char* p = expr;
    const char* c = p;
    valtype sig;
    uint160 keyid;
    bool got_sig = false;
    COMPILER_CTX.symbolic_outputs = true;
    while (*c) {
        while (*c && *c != ',' && *c != ':') ++c;
        char* cs = strndup(p, c-p);
        Value v = Value(cs);
        valtype s = v.data_value();
        free(cs);
        switch (*c) {
        case ':':
            if (got_sig) {
                fprintf(stderr, "parse error (unexpected colon) near %s\n", p);
                return false;
            }
            sig = s;
            got_sig = true;
            break;
        case ',':
        case 0:
            if (!got_sig) {
                fprintf(stderr, "parse error (missing signature) near %s\n", p);
                return false;
            }
            got_sig = false;
            COMPILER_CTX.fake_sigs.insert(sig);
            v.do_hash160();
            keyid = uint160(v.data_value());
            // pretend_valid_map[sig] = s;
            pretend_valid_pubkeys.insert(s);
            CompilerContext::Key ctx_key;
            COMPILER_CTX.FromString(p, c, ctx_key);
            COMPILER_CTX.pkh_map[CKeyID(keyid)] = ctx_key;
            pretend_valid_pubkeys.insert(valtype(ctx_key.begin(), ctx_key.end()));
            // note: we override below; this may lead to issues
            pretend_valid_map[sig] = valtype(ctx_key.begin(), ctx_key.end());
            break;
        }
        p = c = c + (*c != 0);
    }
    return true;
}

void Instance::parse_stack_args(const std::vector<const char*> args) {
    for (auto& v : args) {
        auto z = Value(v).data_value();
        stack.push_back(z);
        if (z.size() == 33) {
            // add if valid pubkey
            CompilerContext::Key key;
            COMPILER_CTX.FromPKBytes(z.begin(), z.end(), key);
        }
    }
}

void Instance::parse_stack_args(size_t argc, char* const* argv, size_t starting_index) {
    for (int i = starting_index; i < argc; i++) {
        stack.push_back(Value(argv[i]).data_value());
    }
}

bool Instance::setup_environment(unsigned int flags) {
    if (tx) {
        // txdata = PrecomputedTransactionData(*tx.get()); // necessary?
        if (txin && txin_vout_index_spent_by_tx > -1) {
            std::vector<CTxOut> spent_outputs;
            spent_outputs.emplace_back(txin->vout[txin_vout_index_spent_by_tx]);
            txdata.Init(*tx.get(), std::move(spent_outputs));
        }
        checker = new TransactionSignatureChecker(tx.get(), tx_internal_vin_index_of_txin > -1 ? tx_internal_vin_index_of_txin : 0, amounts[tx_internal_vin_index_of_txin > -1 ? tx_internal_vin_index_of_txin : 0], txdata);
    } else {
        checker = new BaseSignatureChecker();
    }

    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;

    env = new InterpreterEnv(stack, script, flags, *checker, sigver, &error);
    env->successor_script = successor_script;
    env->pretend_valid_map = pretend_valid_map;
    env->pretend_valid_pubkeys = pretend_valid_pubkeys;
    env->done &= successor_script.size() == 0;
    env->execdata = execdata;
    env->tce = tce;

    return env->operational;
}

bool Instance::at_end() { return env->done; }
bool Instance::at_start() { return env->pc == env->script.begin(); }
std::string Instance::error_string() { return exception_string == "" ? ScriptErrorString(*env->serror) : "exception thrown: " + exception_string; }

bool Instance::step(size_t steps) {
    exception_string = "";
    while (steps > 0) {
        if (env->done) return false;
        try {
            if (!StepScript(*env)) return false;
        } catch (const std::exception& ex) {
            exception_string = ex.what();
            return false;
        }
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
                // verified; is it > 3 chars and can it be a hexstring too?
                if (vlen > 3 && !(vlen & 1)) {
                    std::vector<unsigned char> pushData;
                    if (TryHex(v, pushData)) {
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
            std::vector<unsigned char> pushData;
            if (TryHex(v, pushData)) {
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
        if (!StepScript(*env, it, &script)) {
            fprintf(stderr, "Error: %s\n", ScriptErrorString(*env->serror));
            return false;
        }
    }
    return true;
}

bool Instance::configure_tx_txin() {
    opcodetype opcode;
    std::vector<uint8_t> pushval;
    // no script and no stack; autogenerate from tx/txin
    // the script is the witness stack, last entry, or scriptpubkey
    // the stack is the witness stack minus last entry, in order, or the results of executing the scriptSig
    amounts[tx_internal_vin_index_of_txin] = txin->vout[txin_vout_index_spent_by_tx].nValue;
    btc_logf("input tx index = %" PRId64 "; tx input vout = %" PRId64 "; value = %" PRId64 "\n", tx_internal_vin_index_of_txin, txin_vout_index_spent_by_tx, amounts[tx_internal_vin_index_of_txin]);
    auto& wstack = tx->vin[tx_internal_vin_index_of_txin].scriptWitness.stack;
    auto& scriptSig = tx->vin[tx_internal_vin_index_of_txin].scriptSig;
    CScript scriptPubKey = txin->vout[txin_vout_index_spent_by_tx].scriptPubKey;
    std::vector<const char*> push_del;
    btc_segwit_logf("got witness stack of size %zu\n", wstack.size());
    if (wstack.size() > 0) {
        // segwit
        // P2WPKH:
        //   witness: <sig> <pubkey>
        //   scriptSig: (empty)
        //   scriptPubKey: <version> <20 byte key hash> (0x0014{20-b hash})
        //   the 20 byte hash in the script pub key must match the HASH160 of the pubkey
        //   in the witness
        //   execution: DUP HASH160 <20 byte key hash> EQUALVERIFY CHECKSIG
        // P2WPKH-in-P2SH:
        //   witness: <sig> <pubkey>
        //   scriptSig: [<version> <20 byte key hash>] as single push (0x160014{20-b hash})
        //   scriptPubKey: HASH160 <20-b script hash> EQUAL (0xA914{20-b}87)
        //   scriptPubKey must execute successfully against the single element in scriptSig
        //   the 20 byte hash in the script sig must match the HASH160 of he pubkey in the
        //   witness
        //   execution: OP_DUP OP_HASH160 <20 byte key hash> OP_EQUALVERIFY OP_CHECKSIG
        // P2WSH (1-of-2):
        //   witness: <version> <sig1> <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>
        //   scriptSig: (empty)
        //   scriptPubKey: <version> <32-b hash> (0x0020{32-b})
        //   the 32 byte hash must be equal to the hash of the last entry on the witness stack
        //   execution: witness last element content
        // P2WSH-in-P2SH:
        //   witness: 0 <sig1> <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>
        //   scriptSig: <0 <32-b hash>> (0x220020{32-b hash})
        //   scriptPubKey: HASH160 <20-b hash> EQUAL (0xA914{20-b}87)
        //   scriptPubKey must execute successfully against the single element in scriptSig
        //   the 32 byte hash in the script sig must be equal to the hash of the last entry on the witness stack
        //   execution: witness last element content

        // determining which type:
        // 1. if scriptSig is empty, it is native segwit, otherwise it is P2SH-embedded
        //    if embedded, the validator script is set to the content of the scriptSig (the data inside the push op),
        //    otherwise it is set to the script pub key (as is)
        // 2. if the validator script is of length 22 bytes, it is a P2WPKH, if it is of length
        //    34 bytes, it is a P2WSH

        // process:
        // 1a. if embedded, run the scriptPubKey against the scriptSig and extract the
        //     validator script as the content of the scriptSig.
        // 1b. if native, set the validator to the scriptPubKey
        // 2a. if P2WPKH, set the hash source to the HASH160 of the second (last) element of the
        //     witness
        // 2b. if P2WSH, set the hash source to the SHA256 of the last element of the witness
        // 3.  verify that version=0 (first opcode in validator script)
        // 4.  verify that hash source = the next value in the validator script
        // 5a. for P2WSH, set script = wstack.back()
        // 5b. for P2WPKH, set script = DUP HASH160 ... as defined above

        CScript validation = scriptPubKey;
        Value hashsrc(scriptPubKey);
        std::string source = "script pub key";
        bool wsh;
        uint8_t witprogver; // 0 for pre-taproot, 1 for taproot/tapscript; note that SigVersion has 2 values for taproot (2) vs tapscript (3)
        if (scriptSig.size() > 0) {
            btc_segwit_logf("script sig non-empty; embedded P2SH (extracting payload)\n");
            // Embedded in P2SH -- payload extraction required
            CScript::const_iterator it2 = scriptSig.begin();
            if (!scriptSig.GetOp(it2, opcode, pushval)) {
                fprintf(stderr, "can't parse sig script, or sig script ended prematurely\n");
                return false;
            }
            if (pushval.size() == 0) {
                fprintf(stderr, "sig script did not contain a push op as expected\n");
                return false;
            }
            validation = CScript(pushval.begin(), pushval.end());
            hashsrc = Value(pushval);
            CScript::const_iterator it = scriptPubKey.begin();
            btc_segwit_logf("hash source = %s\n", hashsrc.hex_str().c_str());
            // TODO: run this using interpreter instead
            if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                return false;
            }
            if (opcode != OP_HASH160) {
                fprintf(stderr, "unknown/non-standard script pub key (expected OP_HASH160, got %s)\n", GetOpName(opcode));
                return false;
            }
            if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                return false;
            }
            // pushval = HASH160(scriptSig)
            hashsrc.do_hash160();
            if (uint160(hashsrc.data_value()) != uint160(pushval)) {
                fprintf(stderr, "scriptSig hash does not match the script pub key hash:\n"
                    "- scriptSig: %s\n"
                    "- scriptSig hash: %s\n"
                    "- script pub key: %s\n"
                    "- script pub key given hash: %s\n",
                    HexStr(scriptSig).c_str(),
                    uint160(hashsrc.data).ToString().c_str(),
                    HexStr(scriptPubKey).c_str(),
                    uint160(pushval).ToString().c_str()
                );
                return false;
            }
            source = "script sig";
        }
        switch (validation.size()) {
            case 22: wsh = false; btc_segwit_logf("22 bytes (P2WPKH)\n"); break;
            case 34: wsh = true;  btc_segwit_logf("34 bytes (v0=P2WSH, v1=taproot/tapscript)\n"); break;
            default:
                fprintf(stderr, "expected 22 or 34 byte script inside %s, but got %u bytes: %s\n", source.c_str(), validation.size(), HexStr(validation).c_str());
                return false;
        }
        CScript::const_iterator it = validation.begin();
        if (!validation.GetOp(it, opcode, pushval)) {
            fprintf(stderr, "can't parse %s, or %s ended prematurely\n", source.c_str(), source.c_str());
            return false;
        }
        switch (opcode) {
        case OP_0:
            // version 0 (pre-taproot)
            witprogver = 0;
            sigver = SigVersion::WITNESS_V0;
            break;
        case OP_1:
            // taproot/tapscript
            witprogver = 1;
            // sigver is determined at a later stage for V1
            break;
        default:
            fprintf(stderr, "%s declared version=%s not supported: %s=%s\n", source.c_str(), GetOpName(opcode), source.c_str(), HexStr(validation).c_str());
            return false;
        }
        if (!validation.GetOp(it, opcode, pushval)) {
            fprintf(stderr, "can't parse %s, or %s ended prematurely\n", source.c_str(), source.c_str());
            return false;
        }
        if (pushval.size() != (wsh ? 32 : 20)) {
            fprintf(stderr, "expected %d byte push value, got %zu bytes\n", wsh ? 32 : 20, pushval.size());
            return false;
        }
        auto program = pushval;
        Value wscript(wstack.back());
        size_t wstack_to_stack = wstack.size();
        if (witprogver == 0) {
            // w2pkh/w2sh
            std::string pushval_str;
            std::string wscript_str;
            if (wsh) {
                wscript.do_sha256();
                pushval_str = uint256(pushval).ToString();
                wscript_str = uint256(wscript.data).ToString();
            } else {
                wscript.do_hash160();
                pushval_str = uint160(pushval).ToString();
                wscript_str = uint160(wscript.data).ToString();
            }
            if (wscript.data != pushval) {
                fprintf(stderr, "witness script hash does not match the input script pub key hash:\n"
                    "- witness script: %s\n"
                    "- witness script hash: %s\n"
                    "- script pub key given hash: %s\n",
                    HexStr(wstack.back()).c_str(),
                    wscript_str.c_str(),
                    pushval_str.c_str()
                );
                return false;
            }

            sigver = SigVersion::WITNESS_V0;

            if (!wsh) {
                validation = CScript() << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            } else {
                wstack_to_stack--; // do not include the script on the stack
                validation = CScript(wstack.back().begin(), wstack.back().end());
            }
        } else if (witprogver == 1) {
            auto stack = wstack;
            // taproot/tapscript
            if (program.size() != TAPROOT_PROGRAM_SIZE) {
                fprintf(stderr, "witness program unexpected size: %zu (expected %zu)\n", program.size(), TAPROOT_PROGRAM_SIZE);
                return false;
            }
            // TODO: check if p2sh
            if (stack.size() == 0) {
                fprintf(stderr, "error: witness program was passed an empty witness\n");
                return false;
            }
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Drop annex
                fprintf(stderr, "warning: unknown annex in witness stack\n");
                execdata.m_annex_hash = (CHashWriter(SER_GETHASH, 0) << stack.back()).GetSHA256();
                execdata.m_annex_present = true;
                stack.pop_back();
            } else {
                execdata.m_annex_present = false;
            }
            execdata.m_annex_init = true;
            if (stack.size() == 1) {
                // Key path spending (stack size is 1 after removing optional annex)
                validation = CScript() << program << OP_CHECKSIG;
                sigver = SigVersion::TAPROOT;
            } else {
                // Script path spending (stack size is >1 after removing optional annex)
                auto control = std::move(stack.back());
                stack.pop_back();
                scriptPubKey = CScript(stack.back().begin(), stack.back().end());
                stack.pop_back();
                if (control.size() < TAPROOT_CONTROL_BASE_SIZE || control.size() > TAPROOT_CONTROL_MAX_SIZE || ((control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) != 0) {
                    fprintf(stderr, "control object size %zu is incorrect: %s\n"
                        "- 1. it must not be smaller than the control base size %zu\n"
                        "- 2. it must not be greater than the control max size %zu\n"
                        "- 3. it must be base_size + n*node_size, where base_size = %zu and node_size = %zu\n", control.size(), HexStr(control).c_str(), TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_MAX_SIZE, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE);
                    return false;
                }
                tce = new TaprootCommitmentEnv(control, program, scriptPubKey, &execdata.m_tapleaf_hash);
                execdata.m_tapleaf_hash_init = true;
                if ((control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Tapscript (leaf version 0xc0)
                    execdata.m_validation_weight_left = ::GetSerializeSize(wstack, PROTOCOL_VERSION) + VALIDATION_WEIGHT_OFFSET;
                    execdata.m_validation_weight_left_init = true;
                    sigver = SigVersion::TAPSCRIPT;
                    validation = scriptPubKey;
                    wstack_to_stack = stack.size();
                    // return ExecuteWitnessProgram(std::move(stack), scriptPubKey, flags, SigVersion::TAPSCRIPT, checker, execdata, serror);
                } else {
                    fprintf(stderr, "unable to determine v1 script type (not taproot, not tapscript)\n");
                    return false;
                }
            }
        } else assert(!"should never get here; was a new witprogver added?");

        if (parse_script(std::vector<uint8_t>(validation.begin(), validation.end()))) {
            btc_logf("valid script\n");
        } else {
            fprintf(stderr, "invalid script (witness stack last element)\n");
            return false;
        }
        // put remainder on to-be-parsed stack
        for (size_t i = 0; i < wstack_to_stack; i++) {
            push_del.push_back(strdup(HexStr(wstack[i]).c_str())); // TODO: use as is rather than hexing and dehexing
        }
    } else {
        // legacy
        sigver = SigVersion::BASE;
        script = scriptSig;
        successor_script = scriptPubKey;
    }

    parse_stack_args(push_del);
    while (!push_del.empty()) {
        delete push_del.back();
        push_del.pop_back();
    }

    // extract pubkeys from script
    CScript::const_iterator it = script.begin();
    while (script.GetOp(it, opcode, pushval)) {
        if (pushval.size() == 33) {
            // add if valid pubkey
            CompilerContext::Key key;
            COMPILER_CTX.FromPKBytes(pushval.begin(), pushval.end(), key);
        }
    }

    try {
        msenv = new MSEnv(successor_script, true);
    } catch (const std::exception& ex) {
        printf("miniscript failed to parse script; miniscript support disabled\n");
        msenv = nullptr;
    }

    return true;
}

uint256 Instance::calc_sighash() {
    uint256 hash;
    std::vector<CTxOut> spent_outputs;
    spent_outputs.emplace_back(txin->vout[txin_vout_index_spent_by_tx]);
    txdata = PrecomputedTransactionData();
    txdata.Init(*tx.get(), std::move(spent_outputs));
    if (!SignatureHashSchnorr(hash, execdata, *tx, tx_internal_vin_index_of_txin, 0x00, sigver, txdata)) {
        fprintf(stderr, "Failed to generate schnorr signature hash!\n");
        exit(1);
    }
    return hash;
}
