#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <instance.h>

#include <tinyformat.h>

#include <cliargs.h>

extern "C" {
#include <kerl/kerl.h>
}

int fn_step(const char*);
int fn_rewind(const char*);
int fn_exec(const char*);
int fn_stack(const char*);
int fn_altstack(const char*);
int fn_vfexec(const char*);
int fn_print(const char*);
int fn_tf(const char*);
char* compl_exec(const char*, int);
char* compl_tf(const char*, int);
int print_stack(std::vector<valtype>&, bool raw = false);
int print_bool_stack(std::vector<valtype>&);

bool quiet = false;
bool piping = false;
int count = 0;
char** script_lines;
Instance instance;
InterpreterEnv* env;

struct script_verify_flag {
    std::string str;
    uint32_t id;
    script_verify_flag(std::string str_in, uint32_t id_in) : str(str_in), id(id_in) {}
};

static const std::vector<script_verify_flag> svf {
    #define _(v) script_verify_flag(#v, SCRIPT_VERIFY_##v)
    _(P2SH),
    _(STRICTENC),
    _(DERSIG),
    _(LOW_S),
    _(NULLDUMMY),
    _(SIGPUSHONLY),
    _(MINIMALDATA),
    _(DISCOURAGE_UPGRADABLE_NOPS),
    _(CLEANSTACK),
    _(CHECKLOCKTIMEVERIFY),
    _(CHECKSEQUENCEVERIFY),
    _(WITNESS),
    _(DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
    _(MINIMALIF),
    _(NULLFAIL),
    _(WITNESS_PUBKEYTYPE),
    _(CONST_SCRIPTCODE),
    #undef _
};

static const std::string svf_string(uint32_t flags, std::string separator = " ") {
    std::string s = "";
    while (flags) {
        for (const auto& i : svf) {
            if (flags & i.id) {
                flags ^= i.id;
                s += separator + i.str;
            }
        }
    }
    return s.size() ? s.substr(separator.size()) : "(none)";
}

static const unsigned int svf_get_flag(std::string s) {
    for (const auto& i : svf) if (i.str == s) return i.id;
    return 0;
}

static unsigned int svf_parse_flags(unsigned int in_flags, const char* mod) {
    char buf[128];
    bool adding;
    size_t j = 0;
    for (size_t i = 0; mod[i-(i>0)]; i++) {
        if (!mod[i] || mod[i] == ',') {
            buf[j] = 0;
            if (buf[0] != '+' && buf[0] != '-') {
                fprintf(stderr, "svf_parse_flags(): expected + or - near %s\n", buf);
                exit(1);
            }
            adding = buf[0] == '+';
            unsigned int f = svf_get_flag(&buf[1]);
            if (!f) {
                fprintf(stderr, "svf_parse_flags(): unknown verification flag: %s\n", &buf[1]);
                exit(1);
            }
            if (adding) in_flags |= f; else in_flags &= ~f;
            j = 0;
        } else buf[j++] = mod[i];
    }
    return in_flags;
}

void print_dualstack();

int main(int argc, char* const* argv)
{
    piping = !isatty(fileno(stdin));
    if (piping) btc_logf = btc_logf_dummy;

    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("tx", 'x', req_arg);
    ca.add_option("txin", 'i', req_arg);
    ca.add_option("modify-flags", 'f', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q');

    if (ca.m.count('h')) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [--tx=[amount1,amount2,..:]<hex> [--txin=<hex>] [--modify-flags=<flags>|-f<flags>] [<script> [<stack bottom item> [... [<stack top item>]]]]]\n", argv[0]);
        fprintf(stderr, "if executed with no arguments, an empty script and empty stack is provided\n");
        fprintf(stderr, "to debug transaction signatures, you need to provide the transaction hex (the WHOLE hex, not just the txid) "
            "as well as (SegWit only) every amount for the inputs\n");
        fprintf(stderr, "e.g. if a SegWit transaction abc123... has 2 inputs of 0.1 btc and 0.002 btc, you would do tx=0.1,0.002:abc123...\n");
        fprintf(stderr, "you do not need the amounts for non-SegWit transactions\n");
        fprintf(stderr, "by providing a txin as well as a tx and no script or stack, btcdeb will attempt to set up a debug session for the verification of the given input by pulling the appropriate values out of the respective transactions. you do not need amounts for --tx in this case\n");
        fprintf(stderr, "you can modify verification flags using the --modify-flags command. separate flags using comma (,). prefix with + to enable, - to disable. e.g. --modify-flags=\"-NULLDUMMY,-MINIMALIF\"\n");
        fprintf(stderr, "the standard (enabled by default) flags are:\n・ %s\n", svf_string(STANDARD_SCRIPT_VERIFY_FLAGS, "\n・ ").c_str());
        return 1;
    } else if (!quiet) {
        btc_logf("btcdeb -- type `%s -h` for start up options\n", argv[0]);
    }

    if (!piping) {
        if (std::getenv("DEBUG_SIGHASH")) btc_sighash_logf = btc_logf_stderr;
        if (std::getenv("DEBUG_SIGNING")) btc_sign_logf = btc_logf_stderr;
        if (std::getenv("DEBUG_SEGWIT"))  btc_segwit_logf = btc_logf_stderr;
    }

    unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (ca.m.count('f')) {
        flags = svf_parse_flags(flags, ca.m['f'].c_str());
        if (!quiet) fprintf(stderr, "resulting flags:\n・ %s\n", svf_string(flags, "\n・ ").c_str());
    }

    if (ca.l.size() > 0 && !strncmp(ca.l[0], "tx=", 3)) {
        // backwards compatibility; move into tx
        ca.m['x'] = &ca.l[0][3];
        ca.l.erase(ca.l.begin(), ca.l.begin() + 1);
    }

    // crude check for tx=
    if (ca.m.count('x')) {
        if (!instance.parse_transaction(ca.m['x'].c_str(), true)) {
            return 1;
        }
        if (!quiet) fprintf(stderr, "got %stransaction:\n%s\n", instance.sigver == SigVersion::WITNESS_V0 ? "segwit " : "", instance.tx->ToString().c_str());
    }
    if (ca.m.count('i')) {
        if (!instance.parse_input_transaction(ca.m['i'].c_str())) {
            return 1;
        }
        if (!quiet) fprintf(stderr, "got input tx #%" PRId64 ":\n%s\n", instance.txin_index, instance.txin->ToString().c_str());
    }
    char* script_str = nullptr;
    if (piping) {
        char buf[1024];
        if (!fgets(buf, 1024, stdin)) {
            fprintf(stderr, "warning: no input\n");
        }
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
        script_str = strdup(buf);
    } else if (ca.l.size() > 0) {
        script_str = strdup(ca.l[0]);
        ca.l.erase(ca.l.begin(), ca.l.begin() + 1);
    }
    CScript script;
    if (script_str) {
        if (instance.parse_script(script_str)) {
            if (!quiet) btc_logf("valid script\n");
        } else {
            fprintf(stderr, "invalid script\n");
            return 1;
        }
        free(script_str);
    }

    instance.parse_stack_args(ca.l);

    if (instance.txin && instance.tx && ca.l.size() == 0 && instance.script.size() == 0) {
        opcodetype opcode;
        std::vector<uint8_t> pushval;
        // no script and no stack; autogenerate from tx/txin
        // the script is the witness stack, last entry, or scriptpubkey
        // the stack is the witness stack minus last entry, in order, or the results of executing the scriptSig
        instance.amounts[instance.txin_index] = instance.txin->vout[instance.txin_vout_index].nValue;
        if (!quiet) printf("input tx index = %" PRId64 "; tx input vout = %" PRId64 "; value = %" PRId64 "\n", instance.txin_index, instance.txin_vout_index, instance.amounts[instance.txin_index]);
        auto& wstack = instance.tx->vin[instance.txin_index].scriptWitness.stack;
        auto& scriptSig = instance.tx->vin[instance.txin_index].scriptSig;
        CScript scriptPubKey = instance.txin->vout[instance.txin_vout_index].scriptPubKey;
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
            if (scriptSig.size() > 0) {
                btc_segwit_logf("script sig non-empty; embedded P2SH (extracting payload)\n");
                // Embedded in P2SH -- payload extraction required
                auto it2 = scriptSig.begin();
                if (!scriptSig.GetOp(it2, opcode, pushval)) {
                    fprintf(stderr, "can't parse sig script, or sig script ended prematurely\n");
                    return 1;
                }
                if (pushval.size() == 0) {
                    fprintf(stderr, "sig script did not contain a push op as expected\n");
                    return 1;
                }
                validation = CScript(pushval.begin(), pushval.end());
                hashsrc = Value(pushval);
                CScriptIter it = scriptPubKey.begin();
                btc_segwit_logf("hash source = %s\n", hashsrc.hex_str().c_str());
                // TODO: run this using interpreter instead
                if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                    fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                    return 1;
                }
                if (opcode != OP_HASH160) {
                    fprintf(stderr, "unknown/non-standard script pub key (expected OP_HASH160, got %s)\n", GetOpName(opcode));
                    return 1;
                }
                if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                    fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                    return 1;
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
                    return 1;
                }
                source = "script sig";
            }
            switch (validation.size()) {
                case 22: wsh = false; btc_segwit_logf("22 bytes (P2WPKH)\n"); break;
                case 34: wsh = true;  btc_segwit_logf("34 bytes (P2WSH)\n"); break;
                default:
                    fprintf(stderr, "expected 22 or 34 byte script inside %s, but got %zu bytes\n", source.c_str(), pushval.size());
                    return 1;
            }
            CScriptIter it = validation.begin();
            if (!validation.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse %s, or %s ended prematurely\n", source.c_str(), source.c_str());
                return 1;
            }
            if (opcode != OP_0) {
                fprintf(stderr, "%s declared version=%s not supported: %s=%s\n", source.c_str(), GetOpName(opcode), source.c_str(), HexStr(validation).c_str());
                return 1;
            }
            if (!validation.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse %s, or %s ended prematurely\n", source.c_str(), source.c_str());
                return 1;
            }
            if (pushval.size() != (wsh ? 32 : 20)) {
                fprintf(stderr, "expected %d byte push value, got %zu bytes\n", wsh ? 32 : 20, pushval.size());
                return 1;
            }
            auto program = pushval;
            Value wscript(wstack.back());
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
                return 1;
            }

            instance.sigver = SigVersion::WITNESS_V0;

            size_t wstack_to_stack = wstack.size();
            if (!wsh) {
                validation = CScript() << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            } else {
                wstack_to_stack--; // do not include the script on the stack
                validation = CScript(wstack.back());
            }

            if (instance.parse_script(std::vector<uint8_t>(validation.begin(), validation.end()))) {
                if (!quiet) btc_logf("valid script\n");
            } else {
                fprintf(stderr, "invalid script (witness stack last element)\n");
                return 1;
            }
            // put remainder on to-be-parsed stack
            for (size_t i = 0; i < wstack_to_stack; i++) {
                push_del.push_back(strdup(HexStr(wstack[i]).c_str())); // TODO: use as is rather than hexing and dehexing
            }
        } else {
            // legacy
            instance.sigver = SigVersion::BASE;
            instance.script = scriptPubKey;
            CScript scriptSig = instance.tx->vin[instance.txin_index].scriptSig;
            CScriptIter it = scriptSig.begin();
            while (scriptSig.GetOp(it, opcode, pushval)) {
                if (pushval.size() > 0) {
                    push_del.push_back(strdup(strprintf("0x%s", HexStr(pushval).c_str()).c_str()));
                } else {
                    push_del.push_back(strdup(GetOpName(opcode)));
                }
            }
        }
        instance.parse_stack_args(push_del);
        while (!push_del.empty()) {
            delete push_del.back();
            push_del.pop_back();
        }
    }

    if (!instance.setup_environment(flags)) {
        fprintf(stderr, "failed to initialize script environment: %s\n", instance.error_string());
        return 1;
    }

    env = instance.env;

    CScriptIter it = env->script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    while (env->script.GetOp(it, opcode, vchPushValue)) ++count;
    script_lines = (char**)malloc(sizeof(char*) * count);
    
    it = env->script.begin();
    int i = 0;
    char buf[1024];
    while (env->script.GetOp(it, opcode, vchPushValue)) {
        ++i;
        char* pbuf = buf;
        pbuf += sprintf(pbuf, "#%04d ", i);
        if (vchPushValue.size() > 0) {
            sprintf(pbuf, "%s", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
        } else {
            sprintf(pbuf, "%s", GetOpName(opcode));
        }
        script_lines[i-1] = strdup(buf);
    }

    if (piping) {
        if (!ContinueScript(*env)) {
            fprintf(stderr, "error: %s\n", ScriptErrorString(*env->serror));
            print_dualstack();
        } else {
            print_stack(env->stack, true);
        }
    } else {
        kerl_set_history_file(".btcdeb_history");
        kerl_set_repeat_on_empty(true);
        kerl_set_enable_sensitivity();
        kerl_set_comment_char('#');
        kerl_register("step", fn_step, "Execute one instruction and iterate in the script.");
        kerl_register("rewind", fn_rewind, "Go back in time one instruction.");
        kerl_register("stack", fn_stack, "Print stack content.");
        kerl_register("altstack", fn_altstack, "Print altstack content.");
        kerl_register("vfexec", fn_vfexec, "Print vfexec content.");
        kerl_register("exec", fn_exec, "Execute command.");
        kerl_register("tf", fn_tf, "Transform a value using a given function.");
        kerl_set_completor("exec", compl_exec);
        kerl_set_completor("tf", compl_tf);
        kerl_register("print", fn_print, "Print script.");
        kerl_register_help("help");
        if (!quiet) btc_logf("%d op script loaded. type `help` for usage information\n", count);
        print_dualstack();
        if (env->curr_op_seq < count) {
            printf("%s\n", script_lines[env->curr_op_seq]);
        }
        kerl_run("btcdeb> ");
    }
}

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_step(const char* arg) {
    if (env->done) fail("at end of script\n");
    if (!instance.step()) fail("error: %s\n", instance.error_string());
    print_dualstack();
    if (env->curr_op_seq < count) {
        printf("%s\n", script_lines[env->curr_op_seq]);
    }
    return 0;
}

int fn_rewind(const char* arg) {
    if (instance.at_start()) fail("error: no history to rewind\n");
    if (!instance.rewind()) fail("error: failed to rewind; this is a bug\n");
    print_dualstack();
    if (env->curr_op_seq < count) {
        printf("%s\n", script_lines[env->curr_op_seq]);
    }
    return 0;
}

void print_dualstack() {
    // generate lines for left and right hand side (stack vs script)
    std::vector<std::string> l, r;
    auto it = env->pc;
    char buf[1024];
    opcodetype opcode;
    valtype vchPushValue;
    static int glmax = 7;
    static int grmax = 7;
    int lmax = 0;
    int rmax = 0;
    while (env->script.GetOp(it, opcode, vchPushValue)) {
        char* pbuf = buf;
        if (vchPushValue.size() > 0) {
            sprintf(pbuf, "%s", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
        } else {
            sprintf(pbuf, "%s", GetOpName(opcode));
        }
        auto s = std::string(buf);
        if (s.length() > lmax) lmax = s.length();
        l.push_back(s);
    }
    for (int j = env->stack.size() - 1; j >= 0; j--) {
        auto& it = env->stack[j];
        auto s = it.begin() == it.end() ? "0x" : HexStr(it.begin(), it.end());
        if (s.length() > rmax) rmax = s.length();
        r.push_back(s);
    }
    if (glmax < lmax) glmax = lmax;
    if (grmax < rmax) grmax = rmax;
    lmax = glmax; rmax = grmax;
    int lcap = //66, rcap = 66; // 
    lmax > 66 ? 66 : lmax, rcap = rmax > 66 ? 66 : rmax;
    char lfmt[10], rfmt[10];
    sprintf(lfmt, "%%-%ds", lcap + 1);
    sprintf(rfmt, "%%%ds", rcap);
    printf(lfmt, "script");
    printf("| ");
    printf(rfmt, "stack ");
    printf("\n");
    for (int i = 0; i < lcap; i++) printf("-");
    printf("-+-");
    for (int i = 0; i < rcap; i++) printf("-");
    printf("\n");
    int li = 0, ri = 0;
    while (li < l.size() || ri < r.size()) {
        if (li < l.size()) {
            auto s = l[li++];
            if (s.length() > lcap) s = s.substr(0, lcap-3) + "...";
            printf(lfmt, s.c_str());
        } else {
            printf(lfmt, "");
        }
        printf("| ");
        if (ri < r.size()) {
            auto s = r[ri++];
            if (s.length() > rcap) s = s.substr(0, rcap-3) + "...";
            printf(rfmt, s.c_str());
        }
        printf("\n");
    }
}

int print_stack(std::vector<valtype>& stack, bool raw) {
    if (raw) {
        for (auto& it : stack) printf("%s\n", HexStr(it.begin(), it.end()).c_str());
    } else {
        if (stack.size() == 0) printf("- empty stack -\n");
        int i = 0;
        for (int j = stack.size() - 1; j >= 0; j--) {
            auto& it = stack[j];
            i++;
            printf("<%02d>\t%s%s\n", i, HexStr(it.begin(), it.end()).c_str(), i == 1 ? "\t(top)" : "");
        }
    }
    return 0;
}

int print_bool_stack(std::vector<bool> stack) {
    if (stack.size() == 0) printf("- empty stack -\n");

    int i = 0;
    for (int j = stack.size() - 1; j >= 0; j--) {
        i++;
        printf("<%02d>\t%02x\n", i, (unsigned int) stack[j]);
    }

    return 0;
}

int fn_stack(const char* arg) {
    return print_stack(env->stack);
}

int fn_altstack(const char*) {
    return print_stack(env->altstack);
}

int fn_vfexec(const char*) {
    return print_bool_stack(env->vfExec);
}

static const char* tfs[] = {
    "echo",
    "hex",
    "int",
    "reverse",
    "sha256",
    "ripemd160",
    "hash256",
    "hash160",
    "base58chk-encode",
    "base58chk-decode",
    "bech32-encode",
    "bech32-decode",
    "verify-sig",
    "combine-pubkeys",
    "addr-to-scriptpubkey",
    "scriptpubkey-to-addr",
#ifdef ENABLE_DANGEROUS
    "encode-wif",
    "decode-wif",
    "sign",
    "get-pubkey",
    "combine-privkeys",
#endif // ENABLE_DANGEROUS
    nullptr
};

static const char* tfsh[] = {
    "[*]       show as-is serialized value",
    "[*]       convert into a hex string",
    "[arg]     convert into an integer",
    "[arg]     reverse the value according to the type",
    "[message] perform SHA256",
    "[message] perform RIPEMD160",
    "[message] perform HASH256 (SHA256(SHA256(message))",
    "[message] perform HASH160 (RIPEMD160(SHA256(message))",
    "[pubkey]  encode [pubkey] using base58 encoding (with checksum)",
    "[string]  decode [string] into a pubkey using base58 encoding (with checksum)",
    "[pubkey]  encode [pubkey] using bech32 encoding",
    "[string]  decode [string] into a pubkey using bech32 encoding",
    "[sighash] [pubkey] [signature] verify the given signature for the given sighash and pubkey",
    "[pubkey1] [pubkey2] combine the two pubkeys into one pubkey",
    "[address] convert a base58 encoded address into its corresponding scriptPubKey",
    "[script]  convert a scriptPubKey into its corresponding base58 encoded address",
#ifdef ENABLE_DANGEROUS
    "[privkey] encode [privkey] using the Wallet Import Format",
    "[string]  decode [string] into a private key using the Wallet Import Format",
    "[sighash] [privkey] generate a signature for the given message (sighash) using the given private key",
    "[privkey] get the public key corresponding to the given private key",
    "[privkey1] [privkey2] combine the two private keys into one private key",
#endif // ENABLE_DANGEROUS
    nullptr
};

int _e_echo(Value&& pv)       { pv.println(); return 0; }
int _e_hex(Value&& pv)        { printf("%s\n", pv.hex_str().c_str()); return 0; }
int _e_int(Value&& pv)        { printf("%" PRId64 "\n", pv.int_value()); return 0; }
int _e_reverse(Value&& pv)    { pv.do_reverse(); pv.println(); return 0; }
int _e_sha256(Value&& pv)     { pv.do_sha256(); pv.println(); return 0; }
int _e_ripemd160(Value&& pv)  { pv.do_ripemd160(); pv.println(); return 0; }
int _e_hash256(Value&& pv)    { pv.do_hash256(); pv.println(); return 0; }
int _e_hash160(Value&& pv)    { pv.do_hash160(); pv.println(); return 0; }
int _e_b58ce(Value&& pv)      { pv.do_base58chkenc(); pv.println(); return 0; }
int _e_b58cd(Value&& pv)      { pv.do_base58chkdec(); pv.println(); return 0; }
int _e_b32e(Value&& pv)       { pv.do_bech32enc(); pv.println(); return 0; }
int _e_b32d(Value&& pv)       { pv.do_bech32dec(); pv.println(); return 0; }
int _e_verify_sig(Value&& pv) { pv.do_verify_sig(); pv.println(); return 0; }
int _e_combine_pubkeys(Value&& pv) { pv.do_combine_pubkeys(); pv.println(); return 0; }
int _e_addr_to_spk(Value&& pv) { pv.do_addr_to_spk(); pv.println(); return 0; }
int _e_spk_to_addr(Value&& pv) { pv.do_spk_to_addr(); pv.println(); return 0; }
#ifdef ENABLE_DANGEROUS
int _e_encode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_encode_wif(); pv.println(); return 0; }
int _e_decode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_decode_wif(); pv.println(); return 0; }
int _e_sign(Value&& pv)          { kerl_set_sensitive(true); pv.do_sign(); pv.println(); return 0; }
int _e_get_pubkey(Value&& pv)    { kerl_set_sensitive(true); pv.do_get_pubkey(); pv.println(); return 0; }
int _e_combine_privkeys(Value&& pv) { kerl_set_sensitive(true); pv.do_combine_privkeys(); pv.println(); return 0; }
#endif // ENABLE_DANGEROUS

typedef int (*btcdeb_tfun) (Value&&);
static const btcdeb_tfun tffp[] = {
    _e_echo,
    _e_hex,
    _e_int,
    _e_reverse,
    _e_sha256,
    _e_ripemd160,
    _e_hash256,
    _e_hash160,
    _e_b58ce,
    _e_b58cd,
    _e_b32e,
    _e_b32d,
    _e_verify_sig,
    _e_combine_pubkeys,
    _e_addr_to_spk,
    _e_spk_to_addr,
#ifdef ENABLE_DANGEROUS
    _e_encode_wif,
    _e_decode_wif,
    _e_sign,
    _e_get_pubkey,
    _e_combine_privkeys,
#endif // ENABLE_DANGEROUS
    nullptr
};

int fn_tf(const char* arg) {
    size_t argc;
    char** argv;
    if (kerl_make_argcv(arg, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc == 0) {
        printf("syntax: tf <command> [<param1> [...]]\n");
        printf("transform a value using some function\n");
        printf("available functions are (tf -h for details):");
        for (int i = 0; tfs[i]; i++) {
            printf(" %s", tfs[i]);
        }
        printf("\nexample: tf hex 35        (output: 0x23)\n");
        return 0;
    }
    if (argc == 1 && !strcmp("-h", argv[0])) {
        for (int i = 0; tfs[i]; i++) {
            printf("%-16s %s\n", tfs[i], tfsh[i]);
        }
        return 0;
    }
    int i;
    for (i = 0; tfs[i] && strcmp(tfs[i], argv[0]); i++);
    if (!tfs[i]) {
        printf("unknown function: %s\n", argv[0]);
        return -1;
    }
    if (argc == 1) {
        puts(tfsh[i]);
        return 0;
    }
    return tffp[i](Value(Value::parse_args(argc, (const char**)argv, 1), true));
}

char* compl_tf(const char* text, int continued) {
    static int list_index, len;
    const char *name;

    /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */
    if (!continued) {
        list_index = -1;
        len = strlen(text);
    }

    /* Return the next name which partially matches from the names list. */
    while (tfs[++list_index]) {
        name = tfs[list_index];

        if (strncasecmp(name, text, len) == 0)
            return strdup(name);
    }

    /* If no names matched, then return NULL. */
    return (char *)NULL;
}

int fn_exec(const char* arg) {
    size_t argc;
    char** argv;
    if (kerl_make_argcv(arg, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc < 1) {
        printf("syntax: exec <op> [<op2> [...]]\n");
        printf("to push to stack, simply execute the numeric or hexadecimal value\n");
        return 0;
    }
    instance.eval(argc, argv);
    print_dualstack();
    return 0;
}

int fn_print(const char*) {
    for (int i = 0; i < count; i++) printf("%s%s\n", i == env->curr_op_seq ? " -> " : "    ", script_lines[i]);
    return 0;
}

static const char* opnames[] = {
    // push value
    "OP_0",
    "OP_FALSE",
    "OP_PUSHDATA1",
    "OP_PUSHDATA2",
    "OP_PUSHDATA4",
    "OP_1NEGATE",
    "OP_RESERVED",
    "OP_1",
    "OP_TRUE",
    "OP_2",
    "OP_3",
    "OP_4",
    "OP_5",
    "OP_6",
    "OP_7",
    "OP_8",
    "OP_9",
    "OP_10",
    "OP_11",
    "OP_12",
    "OP_13",
    "OP_14",
    "OP_15",
    "OP_16",

    // control
    "OP_NOP",
    "OP_VER",
    "OP_IF",
    "OP_NOTIF",
    "OP_VERIF",
    "OP_VERNOTIF",
    "OP_ELSE",
    "OP_ENDIF",
    "OP_VERIFY",
    "OP_RETURN",

    // stack ops
    "OP_TOALTSTACK",
    "OP_FROMALTSTACK",
    "OP_2DROP",
    "OP_2DUP",
    "OP_3DUP",
    "OP_2OVER",
    "OP_2ROT",
    "OP_2SWAP",
    "OP_IFDUP",
    "OP_DEPTH",
    "OP_DROP",
    "OP_DUP",
    "OP_NIP",
    "OP_OVER",
    "OP_PICK",
    "OP_ROLL",
    "OP_ROT",
    "OP_SWAP",
    "OP_TUCK",

    // splice ops
    "OP_CAT",
    "OP_SUBSTR",
    "OP_LEFT",
    "OP_RIGHT",
    "OP_SIZE",

    // bit logic
    "OP_INVERT",
    "OP_AND",
    "OP_OR",
    "OP_XOR",
    "OP_EQUAL",
    "OP_EQUALVERIFY",
    "OP_RESERVED1",
    "OP_RESERVED2",

    // numeric
    "OP_1ADD",
    "OP_1SUB",
    "OP_2MUL",
    "OP_2DIV",
    "OP_NEGATE",
    "OP_ABS",
    "OP_NOT",
    "OP_0NOTEQUAL",

    "OP_ADD",
    "OP_SUB",
    "OP_MUL",
    "OP_DIV",
    "OP_MOD",
    "OP_LSHIFT",
    "OP_RSHIFT",

    "OP_BOOLAND",
    "OP_BOOLOR",
    "OP_NUMEQUAL",
    "OP_NULEQUALVERIFY",
    "OP_NUMNOTEQUAL",
    "OP_LESSTHAN",
    "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL",
    "OP_GREATERTHANOREQUAL",
    "OP_MIN",
    "OP_MAX",

    "OP_WITHIN",

    // crypto
    "OP_RIPEMD160",
    "OP_SHA1",
    "OP_SHA256",
    "OP_HASH160",
    "OP_HASH256",
    "OP_CODESEPARATOR",
    "OP_CHECKSIG",
    "OP_CHECKSIGVERIFY",
    "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",

    // expansion
    "OP_NOP1",
    "OP_CHECKLOCKTIMEVERIFY",
    "OP_NOP2",
    "OP_CHECKSEQUENCEVERIFY",
    "OP_NOP3",
    "OP_NOP4",
    "OP_NOP5",
    "OP_NOP6",
    "OP_NOP7",
    "OP_NOP8",
    "OP_NOP9",
    "OP_NOP10",

    // // template matching params
    // "OP_SMALLINTEGER",
    // "OP_PUBKEYS",
    // "OP_PUBKEYHASH",
    // "OP_PUBKEY",
    nullptr,
};

char* compl_exec(const char* text, int continued) {
    static int list_index, len;
	const char *name;

	/* If this is a new word to complete, initialize now.  This includes
	 saving the length of TEXT for efficiency, and initializing the index
	 variable to 0. */
	if (!continued) {
		list_index = -1;
		len = strlen(text);
	}

	/* Return the next name which partially matches from the names list. */
	while (opnames[++list_index]) {
		name = opnames[list_index];

		if (strncasecmp(name, text, len) == 0)
			return strdup(name);
	}

	/* If no names matched, then return NULL. */
	return (char *)NULL;
}
