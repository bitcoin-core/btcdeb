#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <instance.h>

#include <tinyformat.h>

#include <cliargs.h>

extern "C" {
#include <kerl/kerl.h>
}

#include <algo/gausselim.h>

#include <compiler/env.h>
#include <compiler/secp256k1-bridge.h>

int fn_help(const char* args);
int fn_vars(const char* args);
int fn_funs(const char* args);
int fn_debug(const char* args);
int fn_load(const char* args);

int parse(const char* args);

bool debug_tokens = false;
bool debug_trees = false;

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
    env.ctx->vars["G"] = std::make_shared<var>(Value("0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"), true);
    G = env.ctx->vars["G"].get();
    Gx = new var(Value("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
    Gy = new var(Value("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
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
    efun(type);
    efun(int);
    efun(hex);
    efun(echo);
    efun(random);
    efun(jacobi);
    efun(point);
    efun(coords);
    efun(oncurve);
    efun(size);
    efun(map);
    efun(reduce);
    efun(array);
    efun(solve);
    efun(max);
    efun(min);

    kerl_set_history_file(".ecide_history");
    kerl_set_repeat_on_empty(false);
    kerl_set_comment_char('#');
    kerl_register("help", fn_help, "Find out how to use this tool.");
    kerl_register("vars", fn_vars, "Show variables.");
    kerl_register("funs", fn_funs, "Show built-in functions.");
    kerl_register("debug", fn_debug, "Toggle debug flags.");
    kerl_register("load", fn_load, "Execute contents of a file.");
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

    fprintf(stderr, "Echo the string 'Hello World' to the user:\n");
    fprintf(stderr, "> echo(\"hello world\")\n\n");

    fprintf(stderr, "Concatenate the two strings \"hello \" and \"world\":\n");
    fprintf(stderr, "> \"hello \" ++ \"world\"\n\n");

    fprintf(stderr, "==== Function Declarations ====\n\n");

    fprintf(stderr, "Create a function trash256 which returns the tripe sha256 of the input v:\n");
    fprintf(stderr, "> trash256 = (v) { sha256(sha256(sha256(v))) }\n\n");

    fprintf(stderr, "Create and call an anonymous function which reverses a string twice:\n");
    fprintf(stderr, "> hello_world = (v) { reverse(reverse(v)) }(\"hello world\")\n\n");

    fprintf(stderr, "==== Arrays ====\n\n");

    fprintf(stderr, "Create an array containing the integers 1, 2, and 3:\n");
    fprintf(stderr, "> arr = [1,2,3]\n\n");

    fprintf(stderr, "Multiply the contents of 'arr' above with the number 10:\n");
    fprintf(stderr, "> arr *= 10\n\n");

    fprintf(stderr, "Calculate the sha256 hash of the entries in arr into a new variable called hashes:\n");
    fprintf(stderr, "> hashes = sha256(arr)\n\n");

    fprintf(stderr, "==== Debugging ECIDE ====\n\n");

    fprintf(stderr, "Display tokenization results:\n");
    fprintf(stderr, "> debug tokens\n\n");

    fprintf(stderr, "Display treeify results:\n");
    fprintf(stderr, "> debug trees\n\n");

    return 0;
}

int fn_debug(const char* args)
{
    size_t argc;
    char** argv;
    if (kerl_make_argcv(args, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc != 1) {
        fprintf(stderr, "Toggles debug options.\nAvailable options are: tokens, trees\n");
        kerl_free_argcv(argc, argv);
        return -1;
    }
    if (!strcmp(argv[0], "tokens")) {
        debug_tokens = !debug_tokens;
        fprintf(stderr, "debug tokens = %s\n", debug_tokens ? "on" : "off");
    } else if (!strcmp(argv[0], "trees")) {
        debug_trees = !debug_trees;
        fprintf(stderr, "debug trees = %s\n", debug_trees ? "on" : "off");
    } else {
        fprintf(stderr, "unknown flag: %s\n", argv[0]);
    }
    kerl_free_argcv(argc, argv);
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

bool parse_quiet = false;

int fn_load(const char* args)
{
    size_t argc;
    char** argv;
    if (kerl_make_argcv(args, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc != 1) {
        fprintf(stderr, "Loads and executes the content of a file on disk.\n");
        kerl_free_argcv(argc, argv);
        return -1;
    }
    FILE* fp = fopen(argv[0], "r");
    if (!fp) {
        fprintf(stderr, "File not found or access denied: %s\n", argv[0]);
        kerl_free_argcv(argc, argv);
        return -1;
    }
    char* buf = (char*)malloc(1024);
    size_t cap = 1024;
    parse_quiet = true;
    kerl_redirect_input(fp);
    size_t ctr = kerl_get_count();
    kerl_run("");
    size_t line = kerl_get_count() - ctr;
    kerl_redirect_input(NULL);
    parse_quiet = false;
    printf("[%zu lines parsed]\n", line);
    fclose(fp);
    kerl_free_argcv(argc, argv);
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
        if (debug_tokens) {
            printf("<< tokens >>\n");
            tokens->print();
        }
        tree = tiny::treeify(tokens);
        if (debug_trees) {
            printf("<< tree >>\n");
            tree->print();
            printf("\n");
        }
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
    if (!parse_quiet) {
        if (result) {
            // std::shared_ptr<var> v = env.ctx->temps[result];
            env.printvar(result);
            // v->data.println();
        } else if (env.ctx->last_saved != "") {
            env.printvar(env.ctx->last_saved);
            // env.ctx->vars[env.ctx->last_saved]->data.println();
        }
    }
    return 0;
}

#define ARG_CHK(count) if (args.size() != count) throw std::runtime_error(strprintf("invalid number of arguments (" #count " expected, got %zu)", args.size()))
#define CURVE_CHK(v) if (!v->on_curve) throw std::runtime_error("invalid argument (curve point required)");
#define NO_CURVE_CHK(v) if (v->on_curve) throw std::runtime_error("invalid argument (curve points not allowed)");
#define ARG1_NO_CURVE(vfun)             \
    ARG_CHK(1);                         \
    std::shared_ptr<var> v = args[0];   \
    if (!v.get()) throw std::runtime_error("nil argument"); \
    if (v->pref) throw std::runtime_error("complex argument not allowed"); \
    NO_CURVE_CHK(v);                    \
    Value v2(v->data);                  \
    v2.vfun();                          \
    return std::make_shared<var>(v2, false)

#define ARGx_NO_CURVE(vfun)                                                             \
    std::vector<std::shared_ptr<var>> res;                                              \
    if (args.size() == 1 && args[0]->pref) args = env.ctx->arrays.at(args[0]->pref);    \
    for (auto& v : args) {                                                              \
        if (!v.get()) throw std::runtime_error("nil argument");                         \
        if (v->pref) {                                                                  \
            throw std::runtime_error("nested complex arguments not allowed");           \
        }                                                                               \
        NO_CURVE_CHK(v);                                                                \
        Value v2(v->data);                                                              \
        v2.vfun();                                                                      \
        res.push_back(std::make_shared<var>(v2));                                       \
    }                                                                                   \
    if (res.size() > 1) {                                                               \
        tiny::ref ref = env.push_arr(res);                                              \
        return env.pull(ref);                                                           \
    } else {                                                                            \
        return res[0];                                                                  \
    }

std::shared_ptr<var> e_sha256(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_sha256)
}

std::shared_ptr<var> e_reverse(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_reverse);
}

std::shared_ptr<var> e_ripemd160(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_ripemd160);
}
std::shared_ptr<var> e_hash256(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_hash256);
}
std::shared_ptr<var> e_hash160(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_hash160);
}
std::shared_ptr<var> e_base58enc(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_base58enc);
}
std::shared_ptr<var> e_base58dec(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_base58dec);
}
std::shared_ptr<var> e_base58chkenc(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_base58chkenc);
}
std::shared_ptr<var> e_base58chkdec(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_base58chkdec);
}
std::shared_ptr<var> e_bech32enc(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_bech32enc);
}
std::shared_ptr<var> e_bech32dec(std::vector<std::shared_ptr<var>> args) {
    ARGx_NO_CURVE(do_bech32dec);
}

void echo(std::vector<std::shared_ptr<var>>& args, bool& need_nl) {
    for (auto& v : args) {
        if (!v.get()) { need_nl = true; printf("nil"); }
        else if (v->pref) echo(env.ctx->arrays[v->pref], need_nl);
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

std::string _type(const std::shared_ptr<var>& v) {
    if (v->pref) {
        if (env.ctx->arrays.count(v->pref)) {
            return "array";
        } else if (env.ctx->programs.count(v->pref)) {
            return "function";
        } else {
            return "????";
        }
    } else switch (v->data.type) {
    case Value::T_STRING: return "string";
    case Value::T_INT: return "int";
    case Value::T_DATA: return "data";
    case Value::T_OPCODE: return "opcode";
    }
}

std::shared_ptr<var> e_type(std::vector<std::shared_ptr<var>> args) {
    for (auto v : args) {
        printf("%s\n", _type(v).c_str());
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

std::shared_ptr<var> e_jacobi(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    if (v->pref) throw std::runtime_error("complex argument not allowed");
    NO_CURVE_CHK(v);

    v->data.data_value();
    v->data.type = Value::T_DATA;
    secp256k1::num x(v->data.to_string());
    secp256k1::num p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    int rv = x.jacobi(p);
    Value w((uint64_t)rv);
    return std::make_shared<var>(w);
}

void calc_point(std::vector<std::shared_ptr<var>> args, std::vector<uint8_t>& x, std::vector<uint8_t>& y) {
    ARG_CHK(1);
    auto v = args[0];
    CURVE_CHK(v);

    v->data.calc_point(x, y);
}

std::shared_ptr<var> e_coords(std::vector<std::shared_ptr<var>> args) {
    std::vector<uint8_t> x, y;
    calc_point(args, x, y);
    std::shared_ptr<var> vx = std::make_shared<var>(Value(x));
    std::shared_ptr<var> vy = std::make_shared<var>(Value(y));
    return env.pull(env.push_arr(std::vector<std::shared_ptr<var>>{ vx, vy }));
}

std::shared_ptr<var> e_oncurve(std::vector<std::shared_ptr<var>> args) {
    std::vector<uint8_t> x, y;
    calc_point(args, x, y);
    secp256k1::num nx(HexStr(x));
    secp256k1::num ny(HexStr(y));
    secp256k1::num p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    return (((ny * ny) % p) - ((((nx * nx) % p) * nx) % p)) % p == secp256k1::no7 ? env_true : env_false;
}

std::shared_ptr<var> e_point(std::vector<std::shared_ptr<var>> args) {
    // 1 arg (x point, with implicit y sign),
    // 2 arg (x, and boolean y sign)
    if (args.size() < 1 || args.size() > 2) throw std::runtime_error("need either x point (implicit y sign), or x point and y sign bool (true=positive)");
    auto x = args[0];
    NO_CURVE_CHK(x);
    auto y_pos = args.size() == 1 || !args[1]->data.is_null_or_int(0);
    Value v((int64_t)0);
    v.set_point(x->data.data, y_pos);
    return std::make_shared<var>(v, true);
}

size_t _size(const std::shared_ptr<var>& v) {
    if (v->pref) {
        if (env.ctx->arrays.count(v->pref)) {
            return env.ctx->arrays.at(v->pref).size();
        }
        if (env.ctx->programs.count(v->pref)) {
            return env.ctx->programs.at(v->pref)->prog.r->ops();
        }
    }
    switch (v->data.type) {
    case Value::T_DATA: return v->data.data.size();
    case Value::T_STRING: return v->data.str.length();
    default: throw std::runtime_error("invalid type for size operation");
    }
}

std::shared_ptr<var> e_size(std::vector<std::shared_ptr<var>> args) {
    if (args.size() == 0) throw std::runtime_error("at least 1 argument required");
    if (args.size() == 1) {
        return std::make_shared<var>(Value((int64_t)_size(args[0])));
    }
    std::vector<std::shared_ptr<var>> res;
    for (auto& arg : args) {
        res.emplace_back(std::make_shared<var>(Value((int64_t)_size(arg))));
    }
    return env.pull(env.push_arr(res));
}

std::shared_ptr<var> e_max(std::vector<std::shared_ptr<var>> args) {
    if (args.size() == 0) throw std::runtime_error("at least 1 argument required");
    std::shared_ptr<var> max;
    for (auto& arg : args) {
        if (!max.get() || max->data < arg->data) max = arg;
    }
    return max;
}

std::shared_ptr<var> e_min(std::vector<std::shared_ptr<var>> args) {
    if (args.size() == 0) throw std::runtime_error("at least 1 argument required");
    std::shared_ptr<var> min;
    for (auto& arg : args) {
        if (!min.get() || arg->data < min->data) min = arg;
    }
    return min;
}

std::shared_ptr<var> e_solve(std::vector<std::shared_ptr<var>> args) {
    if (args.size() != 2) throw std::runtime_error("at least 2 arguments required");
    auto A = args[0];
    auto b = args[1];
    if (!A->pref || !env.ctx->arrays.count(A->pref)) throw std::runtime_error("first argument must be a matrix");
    auto& Aarr = env.ctx->arrays.at(A->pref);
    // A is an array of arrays
    size_t n = Aarr.size();
    bool size_violation = false;
    for (auto& v : Aarr) {
        if (!v->pref || !env.ctx->arrays.count(v->pref)) throw std::runtime_error("first argument must be a matrix");
        auto& varr = env.ctx->arrays.at(v->pref);
        size_violation |= varr.size() != n;
    }
    if (size_violation) throw std::runtime_error("first argument must be an n-by-n matrix");
    if (!b->pref || !env.ctx->arrays.count(b->pref)) throw std::runtime_error("second argument must be a vector");
    auto& barr = env.ctx->arrays.at(b->pref);
    if (barr.size() != n) throw std::runtime_error("first and second argument must be of the same length");
    // convert to algo format
    algo::vec line(n + 1, 0);
    algo::mat aA(n, line);
    for (size_t i = 0; i < n; ++i) {
        auto& varr = env.ctx->arrays.at(Aarr[i]->pref);
        for (size_t j = 0; j < n; ++j) {
            if (varr[j]->pref) throw std::runtime_error(strprintf("invalid type %s", _type(varr[j])));
            aA[i][j] = varr[j]->data.int_value();
        }
    }
    for (size_t j = 0; j < n; ++j) {
        aA[j][n] = barr[j]->data.int_value();
    }
    algo::gausselim_print(aA);
    auto algo_res = algo::gausselim(aA);
    std::vector<std::shared_ptr<var>> res(algo_res.size());
    for (size_t i = 0; i < algo_res.size(); ++i) {
        res[i] = std::make_shared<var>(Value((int64_t)std::round(algo_res[i])));
    }
    return env.pull(env.push_arr(res));
}

std::shared_ptr<var> e_array(std::vector<std::shared_ptr<var>> args) {
    if (args.size() < 1 || args.size() > 2) throw std::runtime_error("1 or 2 arguments (length[, initfun]) required");
    auto& len = args[0];
    auto initfun = args.size() == 2 ? args[1] : std::shared_ptr<var>();

    int num = len->data.int_value();
    if (num < 0 || num > 10 * 1024 * 1024) throw std::runtime_error("out of bounds array() count (allowed: 0..10M)");

    std::vector<std::shared_ptr<var>> res;
    if (initfun.get()) {
        if (initfun->data.type == Value::T_STRING) {
            // built-in
            if (!env.ctx->fmap.count(initfun->data.str)) throw std::runtime_error("not a function");
            auto f = env.ctx->fmap.at(initfun->data.str);
            for (int64_t i = 0; i < num; ++i) {
                res.push_back(f(std::vector<std::shared_ptr<var>>{std::make_shared<var>(Value(i))}));
            }
        } else if (env.ctx->programs.count(initfun->pref)) {
            auto f = env.ctx->programs.at(initfun->pref);
            for (int64_t i = 0; i < num; ++i) {
                auto rv = env._call(f, std::vector<std::shared_ptr<var>>{std::make_shared<var>(Value(i))});
                res.push_back(env.pull(rv));
            }
        } else throw std::runtime_error("argument 1 must be a function");
    } else {
        for (int64_t i = 0; i < num; ++i) res.push_back(std::make_shared<var>(Value((int64_t)0)));
    }

    return env.pull(env.push_arr(res));
}

std::shared_ptr<var> e_map(std::vector<std::shared_ptr<var>> args) {
    std::vector<std::shared_ptr<var>> res;
    if (args.size() < 2) throw std::runtime_error("at least two arguments (function and array) required");
    auto& progarg = *args[0];
    // TODO: map over strings
    size_t sz = 0;
    std::vector<std::vector<std::shared_ptr<var>>> rargs;
    for (auto& a : args) {
        if (a == args[0]) continue;
        if (!env.ctx->arrays.count(a->pref)) throw std::runtime_error("argument 2+ must be an array");
        auto arr = env.ctx->arrays.at(a->pref);
        if (!sz) sz = arr.size();
        if (sz != arr.size()) throw std::runtime_error(strprintf("arrays of different size encountered (%zu vs %zu)", sz, arr.size()));
        rargs.push_back(arr);
    }
    if (progarg.data.type == Value::T_STRING) {
        // built-in
        if (!env.ctx->fmap.count(progarg.data.str)) throw std::runtime_error("not a function");
        auto f = env.ctx->fmap.at(progarg.data.str);
        for (size_t i = 0; i < sz; ++i) {
            std::vector<std::shared_ptr<var>> ca;
            for (auto& arg : rargs) ca.push_back(arg[i]);
            res.push_back(f(ca));
        }
    } else if (env.ctx->programs.count(progarg.pref)) {
        auto f = env.ctx->programs.at(progarg.pref);
        for (size_t i = 0; i < sz; ++i) {
            std::vector<std::shared_ptr<var>> ca;
            for (auto& arg : rargs) ca.push_back(arg[i]);
            auto rv = env._call(f, ca);
            res.push_back(env.pull(rv));
        }
    } else throw std::runtime_error("argument 1 must be a function");
    return env.pull(env.push_arr(res));
}

std::shared_ptr<var> e_reduce(std::vector<std::shared_ptr<var>> args) {
    if (args.size() < 2) throw std::runtime_error("at least two arguments (function and first array) required");
    auto& progarg = *args[0];
    size_t sz = 0;
    std::vector<std::vector<std::shared_ptr<var>>> rargs;
    for (auto& a : args) {
        if (a == args[0]) continue;
        if (!env.ctx->arrays.count(a->pref)) throw std::runtime_error("argument 2+ must be an array");
        auto arr = env.ctx->arrays.at(a->pref);
        if (!sz) sz = arr.size();
        if (sz != arr.size()) throw std::runtime_error(strprintf("arrays of different size encountered (%zu vs %zu)", sz, arr.size()));
        rargs.push_back(arr);
    }
    if (sz == 0) return std::make_shared<var>(Value((int64_t)0));
    std::shared_ptr<var> res = std::make_shared<var>(Value(std::vector<uint8_t>()));
    if (progarg.data.type == Value::T_STRING) {
        // built-in
        if (!env.ctx->fmap.count(progarg.data.str)) throw std::runtime_error("not a function");
        auto f = env.ctx->fmap.at(progarg.data.str);
        for (size_t i = 0; i < sz; ++i) {
            std::vector<std::shared_ptr<var>> ca;
            for (auto& arg : rargs) ca.push_back(arg[i]);
            ca.push_back(res);
            res = f(ca);
        }
        // for (size_t i = 1; i < arr.size(); ++i) {
        //     auto arg = arr[i];
        //     res = f(std::vector<std::shared_ptr<var>>{arg, res});
        // }
    } else if (env.ctx->programs.count(progarg.pref)) {
        auto f = env.ctx->programs.at(progarg.pref);
        for (size_t i = 0; i < sz; ++i) {
            // printf("reduce(\n");
            // for (auto& arg : rargs) env.printvar(env.refer(arg[i]));
            // if (i > 0) env.printvar(env.refer(res)); else printf("nil");
            // printf(")\n");
            std::vector<std::shared_ptr<var>> ca;
            for (auto& arg : rargs) ca.push_back(arg[i]);
            ca.push_back(res);
            auto rv = env._call(f, ca);
            res = env.pull(rv);
            // printf("= "); env.printvar(rv);
        }
        // for (size_t i = 1; i < arr.size(); ++i) {
        //     auto arg = arr[i];
        //     res = env.pull(env._call(f, std::vector<std::shared_ptr<var>>{arg, res}));
        // }
    } else throw std::runtime_error("argument 1 must be a function");
    return res;
}
