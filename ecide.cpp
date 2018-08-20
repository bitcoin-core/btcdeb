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
    tiny::ref pref = 0;
    bool on_curve = false;
    var(Value data_in, bool on_curve_in = false) : data(data_in), on_curve(on_curve_in) {}
    var(tiny::ref pref_in) : data((int64_t)0), pref(pref_in) {}
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
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 + other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        Value prep = curve_check_and_prep(other, op);
        if (on_curve) prep.do_combine_pubkeys();
        else          prep.do_combine_privkeys();
        return std::make_shared<var>(prep, on_curve);
    }
    std::shared_ptr<var> sub(const var& other) const {
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 - other.data.int64);
            return std::make_shared<var>(v2, false);
        }
        Value x(other.data);
        if (other.on_curve) x.do_negate_pubkey(); else x.do_negate_privkey();
        return add(var(x, other.on_curve), "subtraction");
    }
    std::shared_ptr<var> mul(const var& other) const {
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 * other.data.int64);
            return std::make_shared<var>(v2, false);
        }
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
        if (data.type == Value::T_INT && other.data.type == Value::T_INT) {
            Value v2(data.int64 / other.data.int64);
            return std::make_shared<var>(v2, false);
        }
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

struct context {
    std::map<tiny::ref,tiny::program_t*> programs;
    std::map<std::string, env_func> fmap;
    std::map<std::string, std::shared_ptr<var>> vars;
    std::vector<std::shared_ptr<var>> temps;
    std::string last_saved;
    std::vector<tiny::program_t*> owned_programs;
    context() {}
    context(const context& pre)
    : programs(pre.programs)
    , fmap(pre.fmap)
    , vars(pre.vars)
    , temps(pre.temps)
    , last_saved("")
    {}
    void teardown() {
        for (tiny::program_t* prog : owned_programs) delete prog;
        owned_programs.clear();
    }
};

struct env_t: public tiny::st_callback_table {
    context* ctx;
    std::vector<context> contexts;

    env_t() {
        contexts.resize(1);
        ctx = &contexts[0];
        ctx->temps.push_back(std::shared_ptr<var>(nullptr));
    }

    tiny::ref load(const std::string& variable) override {
        if (ctx->vars.count(variable) == 0) {
            // may be an opcode or something
            Value v(variable.c_str(), variable.length());
            if (v.type != Value::T_STRING) {
                if (v.type != Value::T_OPCODE) {
                    printf("warning: ambiguous token '%s' is treated as a value, but could be a variable\n", variable.c_str());
                }
                std::shared_ptr<var> tmp = std::make_shared<var>(v);
                ctx->temps.push_back(tmp);
                return ctx->temps.size() - 1;
            }
            throw std::runtime_error(strprintf("undefined variable: %s", variable.c_str()));
        }
        auto& v = ctx->vars.at(variable);
        if (v->pref) return v->pref;
        ctx->temps.push_back(v);
        return ctx->temps.size() - 1;
    }
    #define pull(r) ctx->temps[r]
    void  save(const std::string& variable, tiny::ref value) override {
        // do not allow built-ins
        if (ctx->fmap.count(variable)) {
            throw std::runtime_error(strprintf("reserved keyword %s cannot be modified", variable));
        }
        // ensure the variable is not also an opcode
        Value v(variable.c_str());
        if (v.type == Value::T_OPCODE) {
            throw std::runtime_error(strprintf("immutable opcode %s cannot be modified", variable));
        }
        ctx->last_saved = variable;
        ctx->vars[variable] = pull(value);
    }
    tiny::ref bin(tiny::token_type op, tiny::ref lhs, tiny::ref rhs) override {
        auto l = pull(lhs);
        auto r = pull(rhs);
        std::shared_ptr<var> tmp;
        switch (op) {
        case tiny::tok_plus:
            tmp = l->add(*r);
            break;
        case tiny::tok_minus:
            tmp = l->sub(*r);
            break;
        case tiny::tok_mul:
            tmp = l->mul(*r);
            break;
        case tiny::tok_div:
            tmp = l->div(*r);
            break;
        case tiny::tok_concat:
            tmp = l->concat(*r);
            break;
        default:
            throw std::runtime_error(strprintf("invalid binary operation (%s)", tiny::token_type_str[op]));
        }
        ctx->temps.push_back(tmp);
        return ctx->temps.size() - 1;
    }
    tiny::ref unary(tiny::token_type op, tiny::ref val) override {
        throw std::runtime_error("not implemented");
    }
    tiny::ref fcall(const std::string& fname, int argc, tiny::ref* argv) override {
        if (ctx->fmap.count(fname) == 0) {
            if (ctx->vars.count(fname)) {
                auto& v = ctx->vars.at(fname);
                if (v->pref) return pcall(v->pref, argc, argv);
            }
            throw std::runtime_error(strprintf("unknown function %s", fname));
        }
        std::vector<std::shared_ptr<var>> a;
        for (int i = 0; i < argc; i++) {
            a.push_back(pull(argv[i]));
        }
        auto tmp = ctx->fmap[fname](a);
        if (tmp.get()) {
            ctx->temps.push_back(tmp);
            return ctx->temps.size() - 1;
        } else return 0;
    }
    tiny::ref convert(const std::string& value, tiny::token_type type, tiny::token_type restriction) override {
        Value v((int64_t)0);
        switch (restriction) {
        case tiny::tok_undef:
            v = Value(value.c_str());
            break;
        case tiny::tok_hex:
            v = Value(("0x" + value).c_str());
            break;
        case tiny::tok_bin:
            v = Value(("0b" + value).c_str());
            break;
        default:
            throw std::runtime_error(strprintf("unknown restriction token %s", tiny::token_type_str[restriction]));
        }
        auto tmp = std::make_shared<var>(v);
        ctx->temps.push_back(tmp);
        return ctx->temps.size() - 1;
    }
    tiny::ref preg(tiny::program_t* program) override {
        auto pref = std::make_shared<var>((tiny::ref)ctx->temps.size());
        ctx->temps.push_back(pref);
        tiny::ref ref = ctx->temps.size() - 1;
        ctx->programs[ref] = program;
        ctx->owned_programs.push_back(program);
        return ref;
    }
    tiny::ref pcall(tiny::ref program, int argc, tiny::ref* argv) override {
        std::string pname = "<anonymous function>";
        auto& pref = ctx->temps.at(program);
        for (auto& x : ctx->vars) {
            if (x.second == pref) {
                pname = x.first;
                break;
            }
        }
        if (ctx->programs.count(program) == 0) {
            throw std::runtime_error(strprintf("uncallable target %s", pname));
        }
        auto p = ctx->programs[program];
        if (p->argnames.size() != (size_t)argc) {
            throw std::runtime_error(strprintf("invalid number of arguments in call to %s: got %d, expected %zu", pname, argc, p->argnames.size()));
        }
        contexts.emplace_back(*ctx);
        ctx = &contexts.back();
        // pair args with values
        for (int i = 0; i < argc; ++i) {
            save(p->argnames[i], argv[i]);
        }
        tiny::ref rv = p->run(this);
        std::shared_ptr<var> rvp = pull(rv);
        ctx->teardown();
        contexts.pop_back();
        ctx = &contexts.back();
        ctx->temps.push_back(rvp);
        return ctx->temps.size() - 1;
    }
    void printvar(tiny::ref vref) {
        if (ctx->programs.count(vref)) {
            ctx->programs.at(vref)->print();
            printf("\n");
            return;
        }
        ctx->temps[vref]->data.println();
    }
    void printvar(const std::string& varname) {
        if (ctx->vars.count(varname) == 0) return;
        auto& var = ctx->vars.at(varname);
        if (var->pref) var = ctx->temps[var->pref];
        for (tiny::ref i = 1; i < ctx->temps.size(); ++i) {
            if (ctx->temps[i] == var) return printvar(i);
        }
        var->data.println();
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
    VALUE_WARN = false;

    // Set G
    env.ctx->vars["G"] = std::make_shared<var>(Value("ffffffffddddddddffffffffddddddde445123192e953da2402da1730da79c9b"), true);
    G = env.ctx->vars["G"].get();
    #define efun(name) \
        std::shared_ptr<var> e_##name(std::vector<std::shared_ptr<var>> args);\
        env.ctx->fmap[#name] = e_##name
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
    for (const auto& v : env.ctx->vars) {
        fprintf(stderr, "  %s\n", v.first.c_str());
    }
    return 0;
}

int fn_funs(const char* args)
{
    for (const auto& f : env.ctx->fmap) {
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
    size_t capacity = len;
    size_t curlies = 0;
    size_t i = 0;
    while (1) {
        for (; i < len; ++i) {
            curlies += (args[i] == '{') - (args[i] == '}');
        }
        if (curlies > 0) {
            if (kerl_more(&capacity, &len, &args, '}')) {
                printf("user abort\n");
                return -1;
            }
        } else break;
    }

    tiny::token_t* tokens = nullptr;
    tiny::st_t* tree = nullptr;

    tiny::ref result;
    try {
        env.ctx->last_saved = "";
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
        // std::shared_ptr<var> v = env.ctx->temps[result];
        env.printvar(result);
        // v->data.println();
    } else if (env.ctx->last_saved != "") {
        env.printvar(env.ctx->last_saved);
        // env.ctx->vars[env.ctx->last_saved]->data.println();
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
    Value w("string placeholder");
    for (auto v : args) {
        switch (v->data.type) {
        case Value::T_STRING: w.str = "string"; break;
        case Value::T_INT: w.str = "int"; break;
        case Value::T_DATA: w.str = "data"; break;
        case Value::T_OPCODE: w.str = "opcode"; break;
        }
        printf("%s\n", w.str.c_str());
    }
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
