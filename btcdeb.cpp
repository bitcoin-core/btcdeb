#include <cstdio>

#include <script.h>
#include <interpreter.h>
#include <utilstrencodings.h>

extern "C" {
#include <kerl/kerl.h>
}

typedef std::vector<unsigned char> valtype;

int fn_step(const char*);
int fn_stack(const char*);
int fn_altstack(const char*);
int fn_print(const char*);

InterpreterEnv* env;

int count = 0;
char** script_lines;

void print_dualstack();

int main(int argc, const char** argv)
{
    if (argc < 2) {
        printf("syntax: %s <script> [<stack top item> [... [<stack bottom item>]]]\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1]) & 1) {
        printf("error: invalid hex string (length %zu is odd)\n", strlen(argv[1]));
        return 1;
    }
    CScript script;
    std::vector<unsigned char> scriptData(ParseHex(argv[1]));
    if (scriptData.size() != (strlen(argv[1]) >> 1)) {
        printf("failed to parse hex string\n");
        return 1;
    }
    script = CScript(scriptData.begin(), scriptData.end());
    if (script.HasValidOps()) {
        printf("valid script\n");
    } else {
        printf("invalid script\n");
        return 1;
    }
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

    kerl_set_history_file(".btcdeb_history");
    kerl_set_repeat_on_empty(true);
    kerl_register("step", fn_step, "Execute one instruction and iterate in the script.");
    kerl_register("stack", fn_stack, "Print stack content.");
    kerl_register("altstack", fn_altstack, "Print altstack content.");
    kerl_register("print", fn_print, "Print script.");
    kerl_register_help("help");
    printf("%d op script loaded. type `help` for usage information\n", count);
    print_dualstack();
    if (env->curr_op_seq < count) {
        printf("%s\n", script_lines[env->curr_op_seq]);
    }
    kerl_run("btcdeb> ");

    delete env;
}

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_step(const char* arg) {
    if (env->done) fail("at end of script");
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

int print_stack(std::vector<valtype>& stack) {
    if (stack.size() == 0) printf("- empty stack -\n");
    int i = 0;
    for (int j = stack.size() - 1; j >= 0; j--) {
        auto& it = stack[j];
    // }
    // for (auto& it : stack) {
        i++;
        printf("<%02d>\t%s%s\n", i, HexStr(it.begin(), it.end()).c_str(), i == 1 ? "\t(top)" : "");
    }
    return 0;
}

int fn_stack(const char* arg) {
    return print_stack(env->stack);
}

int fn_altstack(const char*) {
    return print_stack(env->altstack);
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
