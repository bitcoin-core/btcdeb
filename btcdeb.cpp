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
bool pipe_in = false;  // xxx | btcdeb
bool pipe_out = false; // btcdeb xxx > file
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
    pipe_in = !isatty(fileno(stdin)) || std::getenv("DEBUG_SET_PIPE_IN");
    pipe_out = !isatty(fileno(stdout)) || std::getenv("DEBUG_SET_PIPE_OUT");
    if (pipe_in || pipe_out) btc_logf = btc_logf_dummy;

    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("tx", 'x', req_arg);
    ca.add_option("txin", 'i', req_arg);
    ca.add_option("modify-flags", 'f', req_arg);
    ca.add_option("select", 's', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q') || pipe_in || pipe_out;

    if (ca.m.count('h')) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [--tx=[amount1,amount2,..:]<hex> [--txin=<hex>] [--modify-flags=<flags>|-f<flags>] [--select=<index>|-s<index>] [<script> [<stack bottom item> [... [<stack top item>]]]]]\n", argv[0]);
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

    if (!pipe_in) {
        if (std::getenv("DEBUG_SIGHASH")) btc_sighash_logf = btc_logf_stderr;
        if (std::getenv("DEBUG_SIGNING")) btc_sign_logf = btc_logf_stderr;
        if (std::getenv("DEBUG_SEGWIT"))  btc_segwit_logf = btc_logf_stderr;
    }

    unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (ca.m.count('f')) {
        flags = svf_parse_flags(flags, ca.m['f'].c_str());
        if (!quiet) fprintf(stderr, "resulting flags:\n・ %s\n", svf_string(flags, "\n・ ").c_str());
    }

    int selected = -1;
    if (ca.m.count('s')) {
        selected = atoi(ca.m['s'].c_str());
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
        if (!quiet) fprintf(stderr, "got %stransaction %s:\n%s\n", instance.sigver == SigVersion::WITNESS_V0 ? "segwit " : "", instance.tx->GetHash().ToString().c_str(), instance.tx->ToString().c_str());
    }
    if (ca.m.count('i')) {
        if (!instance.parse_input_transaction(ca.m['i'].c_str(), selected)) {
            return 1;
        }
        if (!quiet) fprintf(stderr, "got input tx #%" PRId64 " %s:\n%s\n", instance.txin_index, instance.txin->GetHash().ToString().c_str(), instance.txin->ToString().c_str());
    }
    char* script_str = nullptr;
    if (pipe_in) {
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
        if (!instance.configure_tx_txin()) return 1;
    }

    if (!instance.setup_environment(flags)) {
        fprintf(stderr, "failed to initialize script environment: %s\n", instance.error_string());
        return 1;
    }

    env = instance.env;

    std::vector<CScript*> script_ptrs;
    std::vector<std::string> script_headers;

    script_ptrs.push_back(&env->script);
    script_headers.push_back("");
    CScriptIter it = env->script.begin();
    opcodetype opcode;
    valtype vchPushValue, p2sh_script_payload;
    while (env->script.GetOp(it, opcode, vchPushValue)) { p2sh_script_payload = vchPushValue; ++count; }

    CScript p2sh_script;
    bool has_p2sh = false;
    if (env->is_p2sh && env->p2shstack.size() > 0) {
        has_p2sh = true;
        const valtype& p2sh_script_val = env->p2shstack.back();
        p2sh_script = CScript(p2sh_script_val.begin(), p2sh_script_val.end());
    }
    if (instance.successor_script.size()) {
        script_ptrs.push_back(&instance.successor_script);
        script_headers.push_back("<<< scriptPubKey >>>");
        count++;
        it = instance.successor_script.begin();
        while (instance.successor_script.GetOp(it, opcode, vchPushValue)) ++count;
        if ((env->flags & SCRIPT_VERIFY_P2SH) && instance.successor_script.IsPayToScriptHash()) {
            has_p2sh = true;
            p2sh_script = CScript(p2sh_script_payload.begin(), p2sh_script_payload.end());
        }
    }
    if (has_p2sh) {
        script_ptrs.push_back(&p2sh_script);
        script_headers.push_back("<<< P2SH script >>>");
        count++;
        it = p2sh_script.begin();
        while (p2sh_script.GetOp(it, opcode, vchPushValue)) ++count;
    }
    script_lines = (char**)malloc(sizeof(char*) * count);

    int i = 0;
    char buf[1024];
    for (size_t siter = 0; siter < script_ptrs.size(); ++siter) {
        CScript* script = script_ptrs[siter];
        const std::string& header = script_headers[siter];
        if (header != "") script_lines[i++] = strdup(header.c_str());
        it = script->begin();
        while (script->GetOp(it, opcode, vchPushValue)) {
            char* pbuf = buf;
            pbuf += sprintf(pbuf, "#%04d ", i);
            if (vchPushValue.size() > 0) {
                sprintf(pbuf, "%s", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
            } else {
                sprintf(pbuf, "%s", GetOpName(opcode));
            }
            script_lines[i++] = strdup(buf);
        }
    }

    if (pipe_in || pipe_out) {
        if (!ContinueScript(*env)) {
            fprintf(stderr, "error: %s\n", ScriptErrorString(*env->serror));
            print_dualstack();
            return 1;
        }

        print_stack(env->stack, true);
        return 0;
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

inline void svprintscripts(std::vector<std::string>& l, int& lmax, std::vector<CScript*>& scripts, std::vector<std::string>& headers, CScriptIter it) {
    char buf[1024];
    opcodetype opcode;
    valtype vchPushValue;
    bool begun = false;
    for (size_t siter = 0; siter < scripts.size(); ++siter) {
        CScript* script = scripts[siter];

        if (begun) {
            if (headers[siter] != "") {
                if (headers[siter].length() > lmax) lmax = headers[siter].length();
                l.push_back(headers[siter]);
            }
            it = script->begin();
        }

        while (script->GetOp(it, opcode, vchPushValue)) {
            begun = true;
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

        if (it == script->end()) begun = true;
    }
}

void print_dualstack() {
    // generate lines for left and right hand side (stack vs script)
    auto it = env->pc;
    std::vector<std::string> l, r;
    static int glmax = 7;
    static int grmax = 7;
    int lmax = 0;
    int rmax = 0;
    std::vector<CScript*> scripts;
    std::vector<std::string> headers;
    scripts.push_back(&env->script);
    headers.push_back("");
    CScript p2sh_script;
    bool has_p2sh = false;
    if (env->is_p2sh && env->p2shstack.size() > 0) {
        has_p2sh = true;
        const valtype& p2sh_script_val = env->p2shstack.back();
        p2sh_script = CScript(p2sh_script_val.begin(), p2sh_script_val.end());
    }
    if (env->successor_script.size()) {
        scripts.push_back(&env->successor_script);
        headers.push_back("<<< scriptPubKey >>>");
        if ((env->flags & SCRIPT_VERIFY_P2SH) && env->successor_script.IsPayToScriptHash()) {
            has_p2sh = true;
            CScriptIter it = env->script.begin();
            opcodetype opcode;
            valtype vchPushValue, p2sh_script_payload;
            while (env->script.GetOp(it, opcode, vchPushValue)) { p2sh_script_payload = vchPushValue; }
            p2sh_script = CScript(p2sh_script_payload.begin(), p2sh_script_payload.end());
        }
    }
    if (has_p2sh) {
        scripts.push_back(&p2sh_script);
        headers.push_back("<<< P2SH script >>>");
    }
    svprintscripts(l, lmax, scripts, headers, it);

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
    "tweak-pubkey",
    "addr-to-scriptpubkey",
    "scriptpubkey-to-addr",
    "add",
    "sub",
#ifdef ENABLE_DANGEROUS
    "encode-wif",
    "decode-wif",
    "sign",
    "get-pubkey",
    "combine-privkeys",
    "multiply-privkeys",
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
    "[value] [pubkey] multiply the pubkey with the given 32 byte value",
    "[address] convert a base58 encoded address into its corresponding scriptPubKey",
    "[script]  convert a scriptPubKey into its corresponding base58 encoded address",
    "[value1] [value2] add two values together",
    "[value1] [value2] subtract value2 from value1",
#ifdef ENABLE_DANGEROUS
    "[privkey] encode [privkey] using the Wallet Import Format",
    "[string]  decode [string] into a private key using the Wallet Import Format",
    "[sighash] [privkey] generate a signature for the given message (sighash) using the given private key",
    "[privkey] get the public key corresponding to the given private key",
    "[privkey1] [privkey2] combine the two private keys into one private key",
    "[privkey1] [privkey2] multiply a privkey with another",
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
int _e_tweak_pubkey(Value&& pv) { pv.do_tweak_pubkey(); pv.println(); return 0; }
int _e_addr_to_spk(Value&& pv) { pv.do_addr_to_spk(); pv.println(); return 0; }
int _e_spk_to_addr(Value&& pv) { pv.do_spk_to_addr(); pv.println(); return 0; }
int _e_add(Value&& pv)         { pv.do_add(); pv.println(); return 0; }
int _e_sub(Value&& pv)         { pv.do_sub(); pv.println(); return 0; }
#ifdef ENABLE_DANGEROUS
int _e_encode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_encode_wif(); pv.println(); return 0; }
int _e_decode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_decode_wif(); pv.println(); return 0; }
int _e_sign(Value&& pv)          { kerl_set_sensitive(true); pv.do_sign(); pv.println(); return 0; }
int _e_get_pubkey(Value&& pv)    { kerl_set_sensitive(true); pv.do_get_pubkey(); pv.println(); return 0; }
int _e_combine_privkeys(Value&& pv) { kerl_set_sensitive(true); pv.do_combine_privkeys(); pv.println(); return 0; }
int _e_mul_privkeys(Value&& pv)  { kerl_set_sensitive(true); pv.do_multiply_privkeys(); pv.println(); return 0; }
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
    _e_tweak_pubkey,
    _e_addr_to_spk,
    _e_spk_to_addr,
    _e_add,
    _e_sub,
#ifdef ENABLE_DANGEROUS
    _e_encode_wif,
    _e_decode_wif,
    _e_sign,
    _e_get_pubkey,
    _e_combine_privkeys,
    _e_mul_privkeys,
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
