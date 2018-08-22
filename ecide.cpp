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
    std::map<tiny::ref, std::vector<std::shared_ptr<var>>> arrays;
    std::string last_saved;
    std::vector<tiny::program_t*> owned_programs;
    context() {}
    context(const context& pre)
    : programs(pre.programs)
    , fmap(pre.fmap)
    , vars(pre.vars)
    , temps(pre.temps)
    , arrays(pre.arrays)
    , last_saved("")
    {}
    void teardown() {
        for (tiny::program_t* prog : owned_programs) delete prog;
        owned_programs.clear();
    }
};

std::shared_ptr<var> env_true = std::make_shared<var>(Value((int64_t)1));
std::shared_ptr<var> env_false = std::make_shared<var>(Value((int64_t)0));
struct env_t: public tiny::st_callback_table {
    context* ctx;
    std::vector<context> contexts;
    tiny::ref _true, _false;

    env_t() {
        contexts.resize(1);
        ctx = &contexts[0];
        ctx->temps.push_back(std::shared_ptr<var>(nullptr));
        _true = ctx->temps.size();
        ctx->temps.push_back(env_true);
        _false = ctx->temps.size();
        ctx->temps.push_back(env_false);
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
    inline std::shared_ptr<var>& pull(tiny::ref r) { return ctx->temps[r]; }
    tiny::ref refer(std::shared_ptr<var>& v) {
        for (tiny::ref i = 0; i < ctx->temps.size(); ++i) {
            if (ctx->temps[i] == v) return i;
        }
        throw std::runtime_error(strprintf("reference not found (%s)", v->data.to_string()));
        return tiny::nullref;
    }
    void save(const std::string& variable, const std::shared_ptr<var>& value) {
        // do not allow built-ins
        if (ctx->fmap.count(variable)) {
            throw std::runtime_error(strprintf("reserved keyword %s cannot be modified", variable));
        }
        ctx->last_saved = variable;
        ctx->vars[variable] = value;
    }
    void save(const std::string& variable, tiny::ref value) override {
        // ensure the variable is not also an opcode
        Value v(variable.c_str());
        if (v.type == Value::T_OPCODE) {
            throw std::runtime_error(strprintf("immutable opcode %s cannot be modified", variable));
        }
        save(variable, pull(value));
    }
    tiny::ref push_arr(std::vector<std::shared_ptr<var>>& arr) {
        tiny::ref pos = ctx->temps.size();
        ctx->temps.push_back(std::make_shared<var>(pos));
        ctx->arrays[pos] = arr;
        return pos;
    }
    tiny::ref bin(tiny::token_type op, std::shared_ptr<var>& l, std::shared_ptr<var>& r) {
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
    tiny::ref bin(tiny::token_type op, std::shared_ptr<var>& l, tiny::ref rhs) {
        if (ctx->arrays.count(rhs)) {
            auto& arr = ctx->arrays.at(rhs);
            std::vector<std::shared_ptr<var>> res;
            for (auto& v : arr) {
                res.push_back(pull(bin(op, l, v)));
            }
            return push_arr(res);
        }
        auto r = pull(rhs);
        if (!r) throw std::runtime_error(strprintf("undefined reference %zu (RHS)", rhs));
        return bin(op, l, r);
    }
    tiny::ref bin(tiny::token_type op, tiny::ref lhs, std::shared_ptr<var>& r) {
        if (ctx->arrays.count(lhs)) {
            auto& arr = ctx->arrays.at(lhs);
            std::vector<std::shared_ptr<var>> res;
            for (auto& v : arr) {
                res.push_back(pull(bin(op, v, r)));
            }
            return push_arr(res);
        }
        auto l = pull(lhs);
        if (!l) throw std::runtime_error(strprintf("undefined reference %zu (LHS)", lhs));
        return bin(op, l, r);
    }
    tiny::ref bin(tiny::token_type op, tiny::ref lhs, tiny::ref rhs) override {
        if (ctx->arrays.count(lhs)) {
            auto& arr = ctx->arrays.at(lhs);
            std::vector<std::shared_ptr<var>> res;
            for (auto& v : arr) {
                res.push_back(pull(bin(op, v, rhs)));
            }
            return push_arr(res);
        }
        if (ctx->arrays.count(rhs)) {
            auto& arr = ctx->arrays.at(rhs);
            std::vector<std::shared_ptr<var>> res;
            for (auto& v : arr) {
                res.push_back(pull(bin(op, lhs, v)));
            }
            return push_arr(res);
        }
        return bin(op, pull(lhs), pull(rhs));
    }
    tiny::ref compare(std::shared_ptr<var>& a, std::shared_ptr<var>& b, bool invert) {
        auto F = invert ? _true : _false;
        auto T = invert ? _false : _true;
        if (a->pref) return a->pref == b->pref ? T : F;
        return a->data.to_string() == b->data.to_string() ? T : F;
    }
    tiny::ref compare(tiny::ref a, tiny::ref b, bool invert) override {
        auto F = invert ? _true : _false;
        auto T = invert ? _false : _true;
        if (ctx->arrays.count(a)) {
            if (ctx->arrays.count(b) == 0) return F;
            auto aarr = ctx->arrays[a];
            auto barr = ctx->arrays[b];
            if (aarr.size() != barr.size()) return F;
            for (size_t i = 0; i < aarr.size(); ++i) {
                if (_false == compare(aarr[i], barr[i], false)) return F;
            }
            return T;
        }
        return compare(pull(a), pull(b), invert);
    }
    tiny::ref unary(tiny::token_type op, tiny::ref val) override {
        throw std::runtime_error("not implemented");
    }
    tiny::ref fcall(const std::string& fname, tiny::ref args) override {
        if (ctx->fmap.count(fname) == 0) {
            if (ctx->vars.count(fname)) {
                auto& v = ctx->vars.at(fname);
                if (v->pref) return pcall(v->pref, args);
            }
            throw std::runtime_error(strprintf("unknown function %s", fname));
        }
        std::vector<std::shared_ptr<var>> a;
        if (args) {
            if (ctx->arrays.count(args) == 0) {
                throw std::runtime_error(strprintf("fcall() with non-array argument (internal error) - input ref=%zu", args));
            }
            a = ctx->arrays.at(args);
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
    tiny::ref to_array(size_t count, tiny::ref* refs) override {
        std::vector<std::shared_ptr<var>> arr;
        for (size_t i = 0; i < count; ++i) {
            if (refs[i] == 0) throw std::runtime_error(strprintf("nullref exception for reference at index %zu in to_array call", i));
            if (!ctx->temps[refs[i]]) throw std::runtime_error(strprintf("ref #%zu not in temps", refs[i]));
            arr.push_back(pull(refs[i]));
            if (!arr.back()) throw std::runtime_error(strprintf("internal error (null push) for to_array() at index %zu", i));
        }
        return push_arr(arr);
    }
    tiny::ref at(tiny::ref arrayref, tiny::ref indexref) override {
        if (ctx->arrays.count(arrayref) == 0) throw std::runtime_error("object is not an array");
        auto arr = ctx->arrays.at(arrayref);
        auto index = pull(indexref);
        if (index->data.type != Value::T_INT) throw std::runtime_error(strprintf("invalid index %s", index->data.to_string()));
        int64_t i = index->data.int64;
        if (i < -(int64_t)arr.size()) throw std::runtime_error(strprintf("index out of bounds (%ld < %ld)", (long)i, (long)-(int64_t)arr.size()));
        if (i >= arr.size()) throw std::runtime_error(strprintf("index out of bounds (%ld > %ld)", (long)i, (long)arr.size() - 1));
        if (i < 0) i = arr.size() - i;
        return refer(arr[i]);
    }
    tiny::ref preg(tiny::program_t* program) override {
        auto pref = std::make_shared<var>((tiny::ref)ctx->temps.size());
        ctx->temps.push_back(pref);
        tiny::ref ref = ctx->temps.size() - 1;
        ctx->programs[ref] = program;
        ctx->owned_programs.push_back(program);
        return ref;
    }
    tiny::ref pcall(tiny::ref program, tiny::ref args) override {
        if (ctx->arrays.count(program)) {
            // calling an array of programs, presumably
            std::vector<std::shared_ptr<var>> res;
            // note that ctx will jump around for each pcall so we cannot rely on iterators
            for (size_t i = 0; i < ctx->arrays[program].size(); ++i) {
                auto v = ctx->arrays[program][i];
                if (!v->pref) throw std::runtime_error("item in array is not a program");
                res.push_back(pull(pcall(v->pref, args)));
            }
            return push_arr(res);
        }
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
        std::vector<std::shared_ptr<var>> a;
        if (args) {
            if (ctx->arrays.count(args) == 0) {
                throw std::runtime_error(strprintf("pcall() with non-array argument (internal error) - input ref=%zu", args));
            }
            a = ctx->arrays.at(args);
        }
        auto p = ctx->programs[program];
        if (p->argnames.size() != a.size()) {
            throw std::runtime_error(strprintf("invalid number of arguments in call to %s: got %d, expected %zu", pname, a.size(), p->argnames.size()));
        }
        contexts.emplace_back(*ctx);
        ctx = &contexts.back();
        // pair args with values
        for (int i = 0; i < a.size(); ++i) {
            save(p->argnames[i], a[i]);
        }
        tiny::ref rv = p->run(this);
        std::shared_ptr<var> rvp = pull(rv);
        ctx->teardown();
        contexts.pop_back();
        ctx = &contexts.back();
        ctx->temps.push_back(rvp);
        return ctx->temps.size() - 1;
    }
    void printvar_(tiny::ref vref) {
        if (ctx->programs.count(vref)) {
            printf("%s", ctx->programs.at(vref)->to_string().c_str());
            return;
        }
        if (ctx->arrays.count(vref)) {
            printf("[");
            for (auto& x : ctx->arrays.at(vref)) {
                printf("%s", x == ctx->arrays.at(vref)[0] ? "" : ", ");
                if (x->pref) {
                    printvar_(x->pref);
                } else {
                    x->data.print();
                }
            }
            printf("]");
            return;
        }
        ctx->temps[vref]->data.print();
    }
    void printvar(tiny::ref vref) {
        printvar_(vref);
        printf("\n");
        // if (ctx->programs.count(vref)) {
        //     ctx->programs.at(vref)->print();
        //     printf("\n");
        //     return;
        // }
        // if (ctx->arrays.count(vref)) {
        //     printf("[");
        //     for (auto& x : ctx->arrays.at(vref)) {
        //         printf("%s", x == ctx->arrays.at(vref)[0] ? "" : ", ");
        //         x->data.print();
        //     }
        //     printf("]\n");
        //     return;
        // }
        // ctx->temps[vref]->data.println();
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
    efun(echo);
    efun(random);

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
        // tree->print();
        // printf("\n");
        // printf("***** EXEC\n");
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
    if (v->pref) throw std::runtime_error("complex argument not allowed"); \
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

void echo(std::vector<std::shared_ptr<var>>& args, bool& need_nl) {
    for (auto& v : args) {
        if (v->pref) echo(env.ctx->arrays[v->pref], need_nl);
        else if (v->data.type == Value::T_STRING) { need_nl = true; printf("%s", v->data.str.c_str()); }
        else { need_nl = true; v->data.print(); }
    }
    if (need_nl) {
        printf("\n");
        need_nl = false;
    }
}

std::shared_ptr<var> e_echo(std::vector<std::shared_ptr<var>> args) {
    bool need_nl = false;
    echo(args, need_nl);
    return std::shared_ptr<var>(nullptr);
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

void GetRandBytes(unsigned char* buf, int num); // in value.cpp

std::shared_ptr<var> e_random(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    int num = v->data.int_value();
    if (num < 1 || num > 10 * 1024 * 1024) throw std::runtime_error("out of bounds random() count (allowed: 1..10M)");
    Value w((int64_t)0);
    w.type = Value::T_DATA;
    w.data.resize(num);
    unsigned char* buf = w.data.data();
    GetRandBytes(buf, num);
    return std::make_shared<var>(w);
}
