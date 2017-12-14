#include <cstdio>
#include <unistd.h>

#include <script.h>
#include <interpreter.h>
#include <utilstrencodings.h>

extern "C" {
#include <kerl/kerl.h>
}

typedef std::vector<unsigned char> valtype;

int fn_step(const char*);
int fn_exec(const char*);
int fn_stack(const char*);
int fn_altstack(const char*);
int fn_print(const char*);
char* compl_exec(const char*, int);
int print_stack(std::vector<valtype>&, bool raw = false);

InterpreterEnv* env;

bool piping = false;
int count = 0;
char** script_lines;

void print_dualstack();

void btc_logf_dummy(const char* fmt...) {}

int main(int argc, const char** argv)
{
    piping = !isatty(fileno(stdin));
    if (piping) btc_logf = btc_logf_dummy;

    if (argc == 2 && !strcmp(argv[1], "-h")) {
        fprintf(stderr, "syntax: %s [<script> [<stack top item> [... [<stack bottom item>]]]]\n", argv[0]);
        fprintf(stderr, "if executed with no arguments, an empty script and empty stack is provided\n");
        return 1;
    } else{
        btc_logf("btcdeb -- type `%s -h` for start up options\n", argv[0]);
    }
    int stack_idx = 2;
    char* script_str = NULL;
    if (piping) {
        stack_idx--;
        char buf[1024];
        fgets(buf, 1024, stdin);
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
        script_str = strdup(buf);
    } else {
        script_str = argc > 1 ? strdup(argv[1]) : NULL;
    }
    if (script_str) {
        if (strlen(script_str) & 1) {
            fprintf(stderr, "error: invalid hex string (length %zu is odd)\n", strlen(script_str));
            return 1;
        }
    }
    CScript script;
    if (script_str) {
        std::vector<unsigned char> scriptData(ParseHex(script_str));
        if (scriptData.size() != (strlen(script_str) >> 1)) {
            fprintf(stderr, "failed to parse hex string\n");
            return 1;
        }
        script = CScript(scriptData.begin(), scriptData.end());
        if (script.HasValidOps()) {
            btc_logf("valid script\n");
        } else {
            fprintf(stderr, "invalid script\n");
            return 1;
        }
    }
    free(script_str);
    std::vector<valtype> stack;
    BaseSignatureChecker checker;
    ScriptError error;
    for (int i = 2; i < argc; i++) {
        stack.push_back(ParseHex(argv[i]));
    }
    env = new InterpreterEnv(stack, script, 0, checker, SIGVERSION_WITNESS_V0, &error);
    if (!env->operational) {
        fprintf(stderr, "failed to initialize script environment: %s\n", ScriptErrorString(error));
        return 1;
    }

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
        kerl_register("step", fn_step, "Execute one instruction and iterate in the script.");
        kerl_register("stack", fn_stack, "Print stack content.");
        kerl_register("altstack", fn_altstack, "Print altstack content.");
        kerl_register("exec", fn_exec, "Execute command.");
        kerl_set_completor("exec", compl_exec);
        kerl_register("print", fn_print, "Print script.");
        kerl_register_help("help");
        btc_logf("%d op script loaded. type `help` for usage information\n", count);
        print_dualstack();
        if (env->curr_op_seq < count) {
            printf("%s\n", script_lines[env->curr_op_seq]);
        }
        kerl_run("btcdeb> ");
    }

    delete env;
}

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_step(const char* arg) {
    if (env->done) fail("at end of script\n");
    if (!StepScript(*env)) fail("error: %s\n", ScriptErrorString(*env->serror));
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
    int lmax = 0;
    int rmax = 0;
    while (env->script.GetOp(it, opcode, vchPushValue)) {
        char* pbuf = buf;
        // pbuf += sprintf(pbuf, "#%04d ", i);
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
        auto s = HexStr(it.begin(), it.end());
        if (s.length() > rmax) rmax = s.length();
        r.push_back(s);
    }
    int lcap = 66, rcap = 66; // lmax > 66 ? 66 : lmax, rcap = rmax > 66 ? 66 : rmax;
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
    if (stack.size() == 0) printf(raw ? "\n" : "- empty stack -\n");
    int i = 0;
    for (int j = stack.size() - 1; j >= 0; j--) {
        auto& it = stack[j];
    // }
    // for (auto& it : stack) {
        i++;
        if (raw) {
            printf("%s\n", HexStr(it.begin(), it.end()).c_str());
        } else {
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
                        btc_logf("warning: ambiguous input %s is interpreted as a numeric value; use 0x%s to force into hexadecimal interpretation\n", v, v);
                    }
                }
                // can it be an opcode too?
                if (n < 16) {
                    btc_logf("warning: ambiguous input %s is interpreted as a numeric value (%s), not as an opcode (OP_%s). Use OP_%s to force into op code interpretation\n", v, v, v, v);
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
        return 0;
    }
    CScript::const_iterator it = script.begin();
    while (it != script.end()) {
        if (!ExecIterator(*env, script, it, false)) {
            fprintf(stderr, "Error: %s\n", ScriptErrorString(*env->serror));
        }
    }
    print_dualstack();
    return 0;
}

int fn_print(const char*) {
    for (int i = 0; i < count; i++) printf("%s%s\n", i == env->curr_op_seq ? " -> " : "    ", script_lines[i]);
    // auto it = env->script.begin();
    // opcodetype opcode;
    // valtype vchPushValue;
    // int i = 0;
    // while (env->script.GetOp(it, opcode, vchPushValue)) {
    //     ++i;
    //     printf("%s#%04d ", i - 1 == env->curr_op_seq ? " -> " : "    ", i);
    //     if (vchPushValue.size() > 0) {
    //         printf("%s\n", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
    //     } else {
    //         printf("%s\n", GetOpName(opcode));
    //     }
    // }
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
