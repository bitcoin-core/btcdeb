#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <instance.h>

#include <tinyformat.h>

#include <cliargs.h>

extern "C" {
#include <kerl/kerl.h>
}

#include <tinyparser.h>

int fn_help(const char* args);
int fn_vars(const char* args);
int fn_funs(const char* args);

int parse(const char* args);

struct var;

var* G;

struct var {
    Value data;
    bool on_curve = false;
    var(Value data_in, bool on_curve_in = false) : data(data_in), on_curve(on_curve_in) {}
    var() : data((int64_t)0) {}
    Value curve_check_and_prep(const var& other, const std::string& op) const {
        // only works if both are on the same curve
        if (on_curve != other.on_curve) {
            throw std::runtime_error(strprintf("invalid binary operation: variables must be of same type for %s operator", op));
        }
        return Value::prepare_extraction(data, other.data);
    }
    std::shared_ptr<var> add(const var& other, const std::string& op = "addition") const {
        if (data.type == Value::T_STRING && other.data.type == Value::T_STRING) {
            Value v2((int64_t)0);
            v2.type = Value::T_STRING;
            v2.str = data.str + other.data.str;
            return std::make_shared<var>(v2, false);
        }
        Value prep = curve_check_and_prep(other, op);
        if (on_curve) prep.do_combine_pubkeys();
        else          prep.do_combine_privkeys();
        return std::make_shared<var>(prep, on_curve);
    }
    std::shared_ptr<var> sub(const var& other) const {
        Value x(other.data);
        if (other.on_curve) x.do_negate_pubkey(); else x.do_negate_privkey();
        return add(var(x, other.on_curve), "subtraction");
    }
    std::shared_ptr<var> mul(const var& other) const {
        //              on curve        off curve
        // on curve     INVALID         tweak-pubkey
        // off curve    tweak-pubkey    multiply-privkeys
        if (on_curve && other.on_curve) {
            throw std::runtime_error("invalid binary operation: variables cannot both be curve points for multiplication operator");
        }
        if (&other == G) {
            Value prep(data);
            prep.do_get_pubkey();
            return std::make_shared<var>(prep, true);
        }
        if (on_curve) return other.mul(*this);
        Value prep = Value::prepare_extraction(data, other.data);
        if (!other.on_curve) prep.do_multiply_privkeys();
        else prep.do_tweak_pubkey();
        return std::make_shared<var>(prep, other.on_curve);
    }
    std::shared_ptr<var> div(const var& other) const {
        throw std::runtime_error("division not implemented");
    }
    std::shared_ptr<var> concat(const var& other) const {
        Value v(data), v2(other.data);
        v.data_value();
        v2.data_value();
        v.data.insert(v.data.end(), v2.data.begin(), v2.data.end());
        return std::make_shared<var>(v, false);
    }
};

typedef std::shared_ptr<var> (*env_func) (std::vector<std::shared_ptr<var>> args);

struct env_t: public tiny::st_callback_table {
    std::map<std::string, env_func> fmap;
    std::map<std::string, std::shared_ptr<var>> vars;
    std::vector<std::shared_ptr<var>> temps;
    std::string last_saved;

    void* load(const std::string& variable) override {
        if (vars.count(variable) == 0) {
            // may be an opcode or something
            Value v(variable.c_str(), variable.length());
            if (v.type != Value::T_STRING) {
                printf("warning: ambiguous token '%s' is treated as a value, but could be a variable\n", variable.c_str());
                std::shared_ptr<var> tmp = std::make_shared<var>(v);
                temps.push_back(tmp);
                return &temps.back();
            }
            throw std::runtime_error(strprintf("undefined variable: %s", variable.c_str()));
        }
        return &vars.at(variable);
    }
    #define pull(vptr) *(std::shared_ptr<var>*)vptr
    void  save(const std::string& variable, void* value) override {
        last_saved = variable;
        vars[variable] = pull(value);
    }
    void* bin(tiny::token_type op, void* lhs, void* rhs) override {
        auto l = pull(lhs);
        auto r = pull(rhs);
        std::shared_ptr<var> tmp;
        switch (op) {
        case tiny::plus:
            tmp = l->add(*r);
            break;
        case tiny::minus:
            tmp = l->sub(*r);
            break;
        case tiny::mul:
            tmp = l->mul(*r);
            break;
        case tiny::div:
            tmp = l->div(*r);
            break;
        case tiny::concat:
            tmp = l->concat(*r);
            break;
        default:
            throw std::runtime_error(strprintf("invalid binary operation (%s)", tiny::token_type_str[op]));
        }
        temps.push_back(tmp);
        return &temps.back();
    }
    void* unary(tiny::token_type op, void* val) override {
        throw std::runtime_error("not implemented");
    }
    void* fcall(const std::string& fname, int argc, void** argv) override {
        if (fmap.count(fname) == 0) {
            throw std::runtime_error(strprintf("unknown function %s", fname));
        }
        std::vector<std::shared_ptr<var>> a;
        for (int i = 0; i < argc; i++) {
            a.push_back(pull(argv[i]));
        }
        auto tmp = fmap[fname](a);
        if (tmp.get()) {
            temps.push_back(tmp);
            return &temps.back();
        } else return nullptr;
    }
    void* convert(const std::string& value, tiny::token_type type, tiny::token_type restriction) override {
        Value v((uint64_t)0);
        switch (restriction) {
        case tiny::undef:
            v = Value(value.c_str());
            break;
        case tiny::hex:
            v = Value(("0x" + value).c_str());
            break;
        case tiny::bin:
            v = Value(("0b" + value).c_str());
            break;
        default:
            throw std::runtime_error(strprintf("unknown restriction token %s", tiny::token_type_str[restriction]));
        }
        auto tmp = std::make_shared<var>(v);
        temps.push_back(tmp);
        return &temps.back();
    }
    #undef pull
};

env_t env;

int main(int argc, char* const* argv)
{
    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.parse(argc, argv);

    if (ca.m.count('h')) {
        fprintf(stderr, "%s is a console like interface for working with elliptic curves\n", argv[0]);
        fprintf(stderr, "Type 'help' inside the console for further information\n");
        return 1;
    }

    fprintf(stderr, "\n*** NEVER enter private keys which contain real bitcoin ***\n\nECIDE stores history for all commands to the file .ecide_history in plain text.\nTo omit saving to the history file, prepend the command with a space (' ').\n\n");

    VALUE_EXTENDED = true;

    // Set G
    env.vars["G"] = std::make_shared<var>(Value("ffffffffddddddddffffffffddddddde445123192e953da2402da1730da79c9b"), true);
    G = env.vars["G"].get();
    #define efun(name) \
        std::shared_ptr<var> e_##name(std::vector<std::shared_ptr<var>> args);\
        env.fmap[#name] = e_##name
    efun(sha256);
    efun(reverse);
    efun(ripemd160);
    efun(hash256);
    efun(hash160);
    efun(base58enc);
    efun(base58dec);
    efun(base58chkenc);
    efun(base58chkdec);
    efun(bech32enc);
    efun(bech32dec);
    efun(sign);
    efun(type);
    efun(int);
    efun(hex);

    kerl_set_history_file(".ecide_history");
    kerl_set_repeat_on_empty(false);
    kerl_set_comment_char('#');
    kerl_register("help", fn_help, "Find out how to use this tool.");
    kerl_register("vars", fn_vars, "Show variables.");
    kerl_register("funs", fn_funs, "Show built-in functions.");
    kerl_register_fallback(parse);
    kerl_set_enable_whitespaced_sensitivity();
    kerl_run("> ");
}

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_help(const char* args)
{
    fprintf(stderr, "Set a new variable a to the sha256 hash of the string 'hello ECIDE':\n");
    fprintf(stderr, "> a = sha256(\"hello ECIDE\")\n\n");

    fprintf(stderr, "Show the contents of the variable a:\n");
    fprintf(stderr, "> a\n\n");

    fprintf(stderr, "List all defined variables:\n");
    fprintf(stderr, "> vars\n\n");

    fprintf(stderr, "List all built-in functions:\n");
    fprintf(stderr, "> funs\n\n");

    fprintf(stderr, "Multiply a with the sha256 hash of itself:\n");
    fprintf(stderr, "> a = a * sha256(a)\n\n");

    fprintf(stderr, "Get the generator point (public key) for the variable (private key) a:\n");
    fprintf(stderr, "> a*G\n\n");

    return 0;
}

int fn_vars(const char* args)
{
    for (const auto& v : env.vars) {
        fprintf(stderr, "  %s\n", v.first.c_str());
    }
    return 0;
}

int fn_funs(const char* args)
{
    for (const auto& f : env.fmap) {
        fprintf(stderr, " %s", f.first.c_str());
    }
    fprintf(stderr, "\n");
    return 0;
}

int parse(const char* args_in)
{
    size_t len;
    char* args;
    if (kerl_process_citation(args_in, &len, &args)) {
        printf("user abort\n");
        return -1;
    }

    tiny::token_t* tokens = nullptr;
    tiny::st_t* tree = nullptr;

    void* result;
    try {
        env.last_saved = "";
        /*
        printf("***** TOKENIZE\n"); */
        tokens = tiny::tokenize(args);
        free(args);
        args = nullptr;
        /*tokens->print();
        printf("***** PARSE\n"); */
        tree = tiny::treeify(tokens);
        /*tree->print();
        printf("\n");
        printf("***** EXEC\n");*/
        result = tree->eval(&env);
        delete tree;
        delete tokens;
    } catch (std::exception const& ex) {
        if (tree) delete tree;
        if (tokens) delete tokens;
        if (args) free(args);
        fprintf(stderr, "error: %s\n", ex.what());
        return -1;
    }
    if (result) {
        std::shared_ptr<var> v = *(std::shared_ptr<var>*)result;
        v->data.println();
    } else if (env.last_saved != "") {
        env.vars[env.last_saved]->data.println();
    }
    return 0;
}

#define ARG_CHK(count) if (args.size() != count) throw std::runtime_error(strprintf("invalid number of arguments (" #count " expected, got %zu)", args.size()))
#define NO_CURVE_CHK(v) if (v->on_curve) throw std::runtime_error("invalid argument (curve points not allowed)");
#define ARG1_NO_CURVE(vfun)             \
    ARG_CHK(1);                         \
    std::shared_ptr<var> v = args[0];   \
    NO_CURVE_CHK(v);                    \
    Value v2(v->data);                  \
    v2.vfun();                          \
    return std::make_shared<var>(v2, false)

std::shared_ptr<var> e_sha256(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_sha256);
}

std::shared_ptr<var> e_reverse(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_reverse);
}

std::shared_ptr<var> e_ripemd160(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_ripemd160);
}
std::shared_ptr<var> e_hash256(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_hash256);
}
std::shared_ptr<var> e_hash160(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_hash160);
}
std::shared_ptr<var> e_base58enc(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_base58enc);
}
std::shared_ptr<var> e_base58dec(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_base58dec);
}
std::shared_ptr<var> e_base58chkenc(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_base58chkenc);
}
std::shared_ptr<var> e_base58chkdec(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_base58chkdec);
}
std::shared_ptr<var> e_bech32enc(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_bech32enc);
}
std::shared_ptr<var> e_bech32dec(std::vector<std::shared_ptr<var>> args) {
    ARG1_NO_CURVE(do_bech32dec);
}
std::shared_ptr<var> e_sign(std::vector<std::shared_ptr<var>> args) {
    throw std::runtime_error("not implemented");
}

std::shared_ptr<var> e_type(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    Value w("string placeholder");
    switch (v->data.type) {
    case Value::T_STRING: w.str = "string"; break;
    case Value::T_INT: w.str = "int"; break;
    case Value::T_DATA: w.str = "data"; break;
    case Value::T_OPCODE: w.str = "opcode"; break;
    }
    printf("%s\n", w.str.c_str());
    return std::shared_ptr<var>(nullptr); //std::make_shared<var>(w);
}

std::shared_ptr<var> e_int(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    Value w(v->data.int_value());
    return std::make_shared<var>(w);
}

std::shared_ptr<var> e_hex(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    Value w(v->data);
    w.data_value();
    w.type = Value::T_DATA;
    return std::make_shared<var>(w);
}
