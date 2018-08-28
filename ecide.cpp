#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <instance.h>

#include <tinyformat.h>

#include <cliargs.h>

extern "C" {
#include <kerl/kerl.h>
}

#include <compiler/env.h>
#include <compiler/secp256k1-bridge.h>

int fn_help(const char* args);
int fn_vars(const char* args);
int fn_funs(const char* args);
int fn_debug(const char* args);

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
    env.ctx->vars["G"] = std::make_shared<var>(Value("0xffffffffddddddddffffffffddddddde445123192e953da2402da1730da79c9b"), true);
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

    kerl_set_history_file(".ecide_history");
    kerl_set_repeat_on_empty(false);
    kerl_set_comment_char('#');
    kerl_register("help", fn_help, "Find out how to use this tool.");
    kerl_register("vars", fn_vars, "Show variables.");
    kerl_register("funs", fn_funs, "Show built-in functions.");
    kerl_register("debug", fn_debug, "Toggle debug flags.");
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
        return -1;
    }
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
            printf("[%zu curlies]\n", curlies);
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
#define CURVE_CHK(v) if (!v->on_curve) throw std::runtime_error("invalid argument (curve point required)");
#define NO_CURVE_CHK(v) if (v->on_curve) throw std::runtime_error("invalid argument (curve points not allowed)");
#define ARG1_NO_CURVE(vfun)             \
    ARG_CHK(1);                         \
    std::shared_ptr<var> v = args[0];   \
    if (v->pref) throw std::runtime_error("complex argument not allowed"); \
    NO_CURVE_CHK(v);                    \
    Value v2(v->data);                  \
    v2.vfun();                          \
    return std::make_shared<var>(v2, false)

#define ARGx_NO_CURVE(vfun)                                                             \
    std::vector<std::shared_ptr<var>> res;                                              \
    if (args.size() == 1 && args[0]->pref) args = env.ctx->arrays.at(args[0]->pref);    \
    for (auto& v : args) {                                                              \
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

std::shared_ptr<var> e_type(std::vector<std::shared_ptr<var>> args) {
    Value w("string placeholder");
    for (auto v : args) {
        if (v->pref) {
            if (env.ctx->arrays.count(v->pref)) {
                w.str = "array";
            } else if (env.ctx->programs.count(v->pref)) {
                w.str = "function";
            } else {
                w.str = "????";
            }
        } else switch (v->data.type) {
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

std::shared_ptr<var> e_point(std::vector<std::shared_ptr<var>> args) {
    ARG_CHK(1);
    auto v = args[0];
    CURVE_CHK(v);

    std::vector<uint8_t> x, y;
    if (v.get() == G) {
        x = Gx->data.data;
        y = Gy->data.data;
    } else {
        v->data.calc_point(x, y);
    }
    std::shared_ptr<var> vx = std::make_shared<var>(Value(x));
    std::shared_ptr<var> vy = std::make_shared<var>(Value(y));
    return env.pull(env.push_arr(std::vector<std::shared_ptr<var>>{ vx, vy }));
}
