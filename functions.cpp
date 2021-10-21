
#include <sstream>

#include <functions.h>
#include <value.h>
#include <ansi-colors.h>

InterpreterEnv* env;
Instance instance;
int count = 0;
char** script_lines;

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_step(const char* arg) {
    if (env->done) fail("at end of script\n");
    if (!instance.step()) fail("error: %s\n", instance.error_string().c_str());
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

inline void svprintscripts(std::vector<std::string>& l, int& lmax, std::vector<CScript*>& scripts, std::vector<std::string>& headers, CScript::const_iterator it, TaprootCommitmentEnv* tce) {
    char buf[1024];
    opcodetype opcode;
    valtype vchPushValue;
    bool begun = false;
    if (tce) {
        auto desc = tce->Description();
        std::string header = "<<< taproot commitment >>>";
        if (header.length() > lmax) lmax = header.length();
        l.push_back(header);
        for (const auto& s : desc) {
            if (s.length() > lmax) lmax = s.length();
            l.push_back(s);
        }
        header = "<<< committed script >>>";
        l.push_back(header);
    }
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
                sprintf(pbuf, "%s", HexStr(std::vector<uint8_t>(vchPushValue.begin(), vchPushValue.end())).c_str());
            } else {
                sprintf(pbuf, "%s", GetOpName(opcode).c_str());
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
            CScript::const_iterator it = env->script.begin();
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
    svprintscripts(l, lmax, scripts, headers, it, env->tce);

    std::string right_name = "stack ";
    if (env->tce) {
        right_name = "tapscript commitment state ";
        std::vector<std::string> tces;
        tces.push_back(strprintf("i: %d", env->tce->m_i));
        tces.push_back(strprintf("k: %s", HexStr(env->tce->m_k)));
        for (const auto& s : tces) {
            if (s.length() > rmax) rmax = s.length();
            r.push_back(s);
        }
    } else {
        for (int j = env->stack.size() - 1; j >= 0; j--) {
            auto& it = env->stack[j];
            auto s = it.begin() == it.end() ? "0x" : HexStr(std::vector<uint8_t>(it.begin(), it.end()));
            if (s.length() > rmax) rmax = s.length();
            r.push_back(s);
        }
    }

    // if (r.size() > 0 && instance.msenv) r.push_back(""); // spacing between stack and miniscript
    size_t ms_start = r.size();

    // // miniscript representation
    // if (instance.msenv) {
    //     std::istringstream ms(instance.msenv->TreeString(env->curr_op_seq));
    //     for (std::string l; std::getline(ms, l); ) {
    //         if (ansi::length(l) > rmax) rmax = ansi::length(l);
    //         r.push_back(l);
    //     }
    // }

    if (glmax < lmax) glmax = lmax;
    if (grmax < rmax) grmax = rmax;
    lmax = glmax; rmax = grmax;
    int lcap = //66, rcap = 66; // 
    lmax > 66 ? 66 : lmax, rcap = rmax > 66 ? 66 : rmax;
    char lfmt[15], rfmt[14];
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
            // if (ms_start > ri) {
                // printing stack items; right-align, no ansi
                if (s.length() > rcap) s = s.substr(0, rcap-3) + "...";
                printf(rfmt, s.c_str());
            // } else {
            //     // printing miniscript tree; left-align, ansi enabled
            //     if (ansi::length(s) > rcap) s = ansi::substring(s, 0, rcap-3) + "...";
            //     printf("%s", s.c_str());
            // }
        }
        printf("\n");
    }
}

int print_stack(std::vector<valtype>& stack, bool raw) {
    if (raw) {
        for (auto& it : stack) printf("%s\n", HexStr(std::vector<uint8_t>(it.begin(), it.end())).c_str());
    } else {
        if (stack.size() == 0) printf("- empty stack -\n");
        int i = 0;
        for (int j = stack.size() - 1; j >= 0; j--) {
            auto& it = stack[j];
            i++;
            printf("<%02d>\t%s%s\n", i, HexStr(std::vector<uint8_t>(it.begin(), it.end())).c_str(), i == 1 ? "\t(top)" : "");
        }
    }
    return 0;
}

int print_bool_stack(const ConditionStack& stack) {
    if (stack.size() == 0) printf("- empty stack -\n");

    int i = 0;
    for (int j = stack.size() - 1; j >= 0; j--) {
        ++i;
        printf("<%02d>\t%02x\n", i, (unsigned int) stack.at(j));
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

typedef int (*btcdeb_tfun) (Value&&);

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
int _e_verify_sig_compact(Value&& pv) { pv.do_verify_sig_compact(); pv.println(); return 0; }
int _e_combine_pubkeys(Value&& pv) { pv.do_combine_pubkeys(); pv.println(); return 0; }
int _e_tweak_pubkey(Value&& pv) { pv.do_tweak_pubkey(); pv.println(); return 0; }
int _e_pubkey_to_xpubkey(Value&& pv) { pv.do_pubkey_to_xpubkey(); pv.println(); return 0; }
int _e_addr_to_spk(Value&& pv) { pv.do_addr_to_spk(); pv.println(); return 0; }
int _e_spk_to_addr(Value&& pv) { pv.do_spk_to_addr(); pv.println(); return 0; }
int _e_add(Value&& pv)         { pv.do_add(); pv.println(); return 0; }
int _e_sub(Value&& pv)         { pv.do_sub(); pv.println(); return 0; }
int _e_jacobi_sym(Value&& pv)  { pv.do_jacobi_symbol(); pv.println(); return 0; }
int _e_tagged_hash(Value&& pv) { pv.do_tagged_hash(); pv.println(); return 0; }
int _e_taproot_tweak_pubkey(Value&& pv) { pv.do_taproot_tweak_pubkey(); pv.println(); return 0; }
int _e_prefix_compact_size(Value&& pv) { pv.do_prefix_compact_size(); pv.println(); return 0; }
#ifdef ENABLE_DANGEROUS
int _e_taproot_tweak_seckey(Value&& pv) { pv.do_taproot_tweak_seckey(); pv.println(); return 0; }
int _e_encode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_encode_wif(); pv.println(); return 0; }
int _e_decode_wif(Value&& pv)    { kerl_set_sensitive(true); pv.do_decode_wif(); pv.println(); return 0; }
int _e_sign(Value&& pv)          { kerl_set_sensitive(true); pv.do_sign(); pv.println(); return 0; }
int _e_sign_compact(Value&& pv)  { kerl_set_sensitive(true); pv.do_sign_compact(); pv.println(); return 0; }
int _e_sign_schnorr(Value&& pv)  { kerl_set_sensitive(true); pv.do_sign_schnorr(); pv.println(); return 0; }
int _e_get_pubkey(Value&& pv)    { kerl_set_sensitive(true); pv.do_get_pubkey(); pv.println(); return 0; }
int _e_get_xpubkey(Value&& pv)   { kerl_set_sensitive(true); pv.do_get_xpubkey(); pv.println(); return 0; }
int _e_combine_privkeys(Value&& pv) { kerl_set_sensitive(true); pv.do_combine_privkeys(); pv.println(); return 0; }
int _e_mul_privkeys(Value&& pv)  { kerl_set_sensitive(true); pv.do_multiply_privkeys(); pv.println(); return 0; }
#endif // ENABLE_DANGEROUS

struct tf_t {
    const char* name;
    const char* inl; // when used in fn() form
    const char* help;
    btcdeb_tfun fun;
};

static const tf_t tfs[] = {
    #define TFN(help, name, fun) { name, #fun, help, _e_##fun }
    #define TF(help, name) TFN(help, #name, name)
    TFN("[address] convert a base58 encoded address into its corresponding scriptPubKey", "addr-to-scriptpubkey", addr_to_spk),
    TF ("[value1] [value2] add two values together", add),
    TFN("[string]  decode [string] into a pubkey using bech32 encoding", "bech32-decode", b32d),
    TFN("[pubkey]  encode [pubkey] using bech32 encoding", "bech32-encode", b32e),
    TFN("[string]  decode [string] into a pubkey using base58 encoding (with checksum)", "base58chk-decode", b58cd),
    TFN("[pubkey]  encode [pubkey] using base58 encoding (with checksum)", "base58chk-encode", b58ce),
    TFN("[pubkey1] [pubkey2] combine the two pubkeys into one pubkey", "combine-pubkeys", combine_pubkeys),
    TF ("[*]       show as-is serialized value", echo),
    TF ("[message] perform HASH160 (RIPEMD160(SHA256(message))", hash160),
    TF ("[message] perform HASH256 (SHA256(SHA256(message))", hash256),
    TF ("[*]       convert into a hex string", hex),
    TF ("[arg]     convert into an integer", int),
    TFN("[n] ([k]) calculate the Jacobi symbol for n modulo k, where k defaults to the secp256k1 field size", "jacobi-symbol", jacobi_sym),
    TFN("[value] prefix [value] with its compact size encoded byte length", "prefix-compact-size", prefix_compact_size),
    TFN("[pubkey] convert the given pubkey into an x-only pubkey, as those used in taproot/tapscript", "pubkey-to-xpubkey", pubkey_to_xpubkey),
    TF ("[arg]     reverse the value according to the type", reverse),
    TF ("[message] perform RIPEMD160", ripemd160),
    TF ("[message] perform SHA256", sha256),
    TFN("[script]  convert a scriptPubKey into its corresponding base58 encoded address", "scriptpubkey-to-addr", spk_to_addr),
    TF ("[value1] [value2] subtract value2 from value1", sub),
    TFN("[tag] [message] generate the [tag]ged hash of [message]", "tagged-hash", tagged_hash),
    TFN("[pubkey] [tweak] tweak the pubkey with the tweak", "taproot-tweak-pubkey", taproot_tweak_pubkey),
    TFN("[value] [pubkey] multiply the pubkey with the given 32 byte value", "tweak-pubkey", tweak_pubkey),
    TFN("[sighash] [pubkey] [signature] verify the given signature for the given sighash and pubkey (der)", "verify-sig", verify_sig),
    TFN("[sighash] [pubkey] [signature] verify the given signature for the given sighash and pubkey (compact)", "compact-verify-sig", verify_sig_compact),
#ifdef ENABLE_DANGEROUS
    TFN("[privkey1] [privkey2] combine the two private keys into one private key", "combine-privkeys", combine_privkeys),
    TFN("[string]  decode [string] into a private key using the Wallet Import Format", "decode-wif", decode_wif),
    TFN("[privkey] encode [privkey] using the Wallet Import Format", "encode-wif", encode_wif),
    TFN("[privkey] get the public key corresponding to the given private key", "get-pubkey", get_pubkey),
    TFN("[privkey] get the x-only public key corresponding to the given private key", "get-xpubkey", get_xpubkey),
    TFN("[privkey1] [privkey2] multiply a privkey with another", "multiply-privkeys", mul_privkeys),
    TF ("[sighash] [privkey] generate an ECDSA signature for the given message (sighash) using the given private key (der)", sign),
    TFN("[sighash] [privkey] generate an ECSDA signature for the given message (sighash) using the given private key (compact)", "compact-sign", sign_compact),
    TF ("[sighash] [privkey] generate a Schnorr signature for the given message (sighash) using the given private key (der)", sign_schnorr),
    TFN("[privkey] [tweak] tweak the given private key with the tweak", "taproot-tweak-seckey", taproot_tweak_seckey),
#endif // ENABLE_DANGEROUS
    { "", "", nullptr }
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
        for (int i = 0; tfs[i].fun; ++i) {
            printf(" %s", tfs[i].name);
        }
        printf("\nexample: tf hex 35        (output: 0x23)\n");
        return 0;
    }
    if (argc == 1 && !strcmp("-h", argv[0])) {
        for (int i = 0; tfs[i].fun; i++) {
            printf("%-16s %s\n", tfs[i].name, tfs[i].help);
        }
        printf("\nThe inline operators have slightly different names; they are called:");
        for (int i = 0; tfs[i].fun; i++) {
            printf(" %s", tfs[i].inl);
        }
        printf("\n");
        return 0;
    }
    int i;
    for (i = 0; tfs[i].fun && strcmp(tfs[i].name, argv[0]); i++);
    if (!tfs[i].fun) {
        printf("unknown function: %s\n", argv[0]);
        return -1;
    }
    if (argc == 1) {
        puts(tfs[i].help);
        return 0;
    }
    int rv;
    try {
        rv = tfs[i].fun(Value(Value::parse_args(argc, (const char**)argv, 1), true));
    } catch (std::exception const& ex) {
        fprintf(stderr, "exception: %s\n", ex.what());
        rv = -1;
    }
    kerl_free_argcv(argc, argv);
    return rv;
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
    while (tfs[++list_index].fun) {
        name = tfs[list_index].name;

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
        kerl_free_argcv(argc, argv);
        return 0;
    }
    instance.eval(argc, argv);
    print_dualstack();
    kerl_free_argcv(argc, argv);
    return 0;
}

int fn_print(const char*) {
    for (int i = 0; i < count; i++) printf("%s%s\n", i == env->curr_op_seq ? " -> " : "    ", script_lines[i]);
    return 0;
}
