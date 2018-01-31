#include <cstdio>
#include <unistd.h>

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
int fn_print(const char*);
int fn_tf(const char*);
char* compl_exec(const char*, int);
char* compl_tf(const char*, int);
int print_stack(std::vector<valtype>&, bool raw = false);

bool quiet = false;
bool piping = false;
int count = 0;
char** script_lines;
Instance instance;
InterpreterEnv* env;

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
    ca.parse(argc, argv);
    quiet = ca.m.count('q');

    if (ca.m.count('h')) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [--tx=[amount1,amount2,..:]<hex> [--txin=<hex>] [<script> [<stack bottom item> [... [<stack top item>]]]]]\n", argv[0]);
        fprintf(stderr, "if executed with no arguments, an empty script and empty stack is provided\n");
        fprintf(stderr, "to debug transaction signatures, you need to provide the transaction hex (the WHOLE hex, not just the txid) "
            "as well as (SegWit only) every amount for the inputs\n");
        fprintf(stderr, "e.g. if a SegWit transaction abc123... has 2 inputs of 0.1 btc and 0.002 btc, you would do tx=0.1,0.002:abc123...\n");
        fprintf(stderr, "you do not need the amounts for non-SegWit transactions\n");
        fprintf(stderr, "by providing a txin as well as a tx and no script or stack, btcdeb will attempt to set up a debug session for the verification of the given input by pulling the appropriate values out of the respective transactions. you do not need amounts for --tx in this case\n");
        return 1;
    } else if (!quiet) {
        btc_logf("btcdeb -- type `%s -h` for start up options\n", argv[0]);
    }

    if (!piping) {
        if (std::getenv("DEBUG_SIGHASH")) btc_sighash_logf = btc_logf_stderr;
        if (std::getenv("DEBUG_SIGNING")) btc_sign_logf = btc_logf_stderr;
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
        if (!quiet) fprintf(stderr, "got %stransaction:\n%s\n", instance.sigver == SIGVERSION_WITNESS_V0 ? "segwit " : "", instance.tx->ToString().c_str());
    }
    if (ca.m.count('i')) {
        if (!instance.parse_input_transaction(ca.m['i'].c_str())) {
            return 1;
        }
        if (!quiet) fprintf(stderr, "got input tx #%lld:\n%s\n", instance.txin_index, instance.txin->ToString().c_str());
    }
    char* script_str = nullptr;
    if (piping) {
        char buf[1024];
        fgets(buf, 1024, stdin);
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
    }
    free(script_str);

    instance.parse_stack_args(ca.l);

    if (instance.txin && instance.tx && ca.l.size() == 0 && instance.script.size() == 0) {
        opcodetype opcode;
        std::vector<uint8_t> pushval;
        // no script and no stack; autogenerate from tx/txin
        // the script is the witness stack, last entry, or scriptpubkey
        // the stack is the witness stack minus last entry, in order, or the results of executing the scriptSig
        instance.amounts[instance.txin_index] = instance.txin->vout[instance.txin_vout_index].nValue;
        if (!quiet) printf("input tx index = %lld; tx input vout = %lld; value = %lld\n", instance.txin_index, instance.txin_vout_index, instance.amounts[instance.txin_index]);
        auto& wstack = instance.tx->vin[instance.txin_index].scriptWitness.stack;
        CScript scriptPubKey = instance.txin->vout[instance.txin_vout_index].scriptPubKey;
        std::vector<const char*> push_del;
        if (wstack.size() > 0) {
            // segwit
            // for segwit, the scriptpubkey of the input must be <version> <32 byte push> and the 32 byte push
            // must be equal to the hash of the script; we also only support version 0
            auto it = scriptPubKey.begin();
            if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                return 1;
            }
            if (opcode != OP_0) {
                fprintf(stderr, "script pub key declared version not supported: scriptPubKey=%s\n", HexStr(scriptPubKey).c_str());
                return 1;
            }
            if (!scriptPubKey.GetOp(it, opcode, pushval)) {
                fprintf(stderr, "can't parse script pub key, or script pub key ended prematurely\n");
                return 1;
            }
            if (pushval.size() != 32) {
                fprintf(stderr, "expected 32 byte push value, got %zu bytes\n", pushval.size());
                return 1;
            }
            Value wscript(wstack.back());
            wscript.do_sha256();
            if (uint256(wscript.data) != uint256(pushval)) {
                fprintf(stderr, "witness script hash does not match the input script pub key hash:\n"
                    "- witness script: %s\n"
                    "- witness script hash: %s\n"
                    "- script pub key given hash: %s\n",
                    HexStr(wstack.back()).c_str(),
                    uint256(wscript.data).ToString().c_str(),
                    uint256(pushval).ToString().c_str()
                );
                return 1;
            }

            instance.sigver = SIGVERSION_WITNESS_V0;
            if (instance.parse_script(wstack.back())) {
                if (!quiet) btc_logf("valid script\n");
            } else {
                fprintf(stderr, "invalid script (witness stack last element)\n");
                return 1;
            }
            // put remainder on to-be-parsed stack
            for (size_t i = 0; i+1 < wstack.size(); i++) {
                push_del.push_back(strdup(HexStr(wstack[i]).c_str())); // TODO: use as is rather than hexing and dehexing
            }
        } else {
            // legacy
            instance.sigver = SIGVERSION_BASE;
            instance.script = scriptPubKey;
            CScript scriptSig = instance.tx->vin[instance.txin_index].scriptSig;
            auto it = scriptSig.begin();
            while (scriptSig.GetOp(it, opcode, pushval)) {
                if (pushval.size() > 0)
                    push_del.push_back(strdup(HexStr(pushval).c_str()));
                else
                    push_del.push_back(strdup(strprintf("%02x", opcode).c_str()));
            }
        }
        instance.parse_stack_args(push_del);
        while (!push_del.empty()) {
            delete push_del.back();
            push_del.pop_back();
        }
    }

    if (!instance.setup_environment()) {
        fprintf(stderr, "failed to initialize script environment: %s\n", instance.error_string());
        return 1;
    }

    env = instance.env;

    auto it = env->script.begin();
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
        kerl_set_comment_char('#');
        kerl_register("step", fn_step, "Execute one instruction and iterate in the script.");
        kerl_register("rewind", fn_rewind, "Go back in time one instruction.");
        kerl_register("stack", fn_stack, "Print stack content.");
        kerl_register("altstack", fn_altstack, "Print altstack content.");
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
    int i = 0;
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

int fn_stack(const char* arg) {
    return print_stack(env->stack);
}

int fn_altstack(const char*) {
    return print_stack(env->altstack);
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
#ifdef ENABLE_DANGEROUS
    "encode-wif",
    "decode-wif",
    "sign",
    "get-pubkey",
    "combine-privkeys",
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
#ifdef ENABLE_DANGEROUS
int _e_encode_wif(Value&& pv)    { pv.do_encode_wif(); pv.println(); return 0; }
int _e_decode_wif(Value&& pv)    { pv.do_decode_wif(); pv.println(); return 0; }
int _e_sign(Value&& pv)          { pv.do_sign(); pv.println(); return 0; }
int _e_get_pubkey(Value&& pv)    { pv.do_get_pubkey(); pv.println(); return 0; }
int _e_combine_privkeys(Value&& pv) { pv.do_combine_privkeys(); pv.println(); return 0; }
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
    if (argc < 2) {
        printf("syntax: tf <command> <param1> [...]\n");
        printf("transform a value using some function\n");
        printf("available functions are:");
        for (int i = 0; tfs[i]; i++) {
            printf(" %s", tfs[i]);
        }
        printf("\nexample: tf hex 35        (output: 0x23)\n");
        return 0;
    }
    int i;
    for (i = 0; tfs[i] && strcmp(tfs[i], argv[0]); i++);
    if (!tfs[i]) {
        printf("unknown function: %s\n", argv[0]);
        return -1;
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
