// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_compiler_env_h_
#define included_compiler_env_h_

#include <inttypes.h>

#include <tinyformat.h>

#include <compiler/tinyparser.h>

#include <compiler/secp256k1-bridge.h>

#include <compiler/var.h>


typedef std::shared_ptr<var> (*env_func) (std::vector<std::shared_ptr<var>> args);

struct context {
    std::map<tiny::ref,tiny::program_t*> programs;
    std::map<std::string, env_func> fmap;
    std::map<std::string, std::shared_ptr<var>> vars;
    std::vector<std::shared_ptr<var>> temps;
    std::map<tiny::ref, std::vector<std::shared_ptr<var>>> arrays;
    std::string last_saved;
    std::vector<tiny::program_t*> owned_programs;
    std::vector<std::shared_ptr<var>> mods;
    std::shared_ptr<var> mod;
    context() {}
    context(const context& pre)
    : programs(pre.programs)
    , fmap(pre.fmap)
    , vars(pre.vars)
    , temps(pre.temps)
    , arrays(pre.arrays)
    , last_saved("")
    , mods(pre.mods)
    , mod(pre.mod)
    {}
    void teardown() {
        for (tiny::program_t* prog : owned_programs) delete prog;
        owned_programs.clear();
    }
};

struct env_t: public tiny::st_callback_table {
#define ARRTHRU(reference, callback...) \
        if (ctx->arrays.count(reference)) { \
            auto& arr = ctx->arrays.at(reference); \
            std::vector<std::shared_ptr<var>> res; \
            for (auto& v : arr) { \
                res.push_back(pull(callback)); \
            } \
            return push_arr(res); \
        }

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

    inline tiny::ref refer(const std::shared_ptr<var>& v, bool created = false) {
        if (!created) {
            for (tiny::ref i = 0; i < ctx->temps.size(); ++i) {
                if (ctx->temps[i] == v) return i;
            }
        }
        ctx->temps.push_back(v);
        return ctx->temps.size() - 1;
    }
    tiny::ref load(const std::string& variable) override {
        if (ctx->fmap.count(variable)) {
            return refer(std::make_shared<var>(variable), true);
        }
        if (ctx->vars.count(variable) == 0) {
            // may be an opcode or something
            Value v(variable.c_str(), variable.length());
            if (v.type != Value::T_STRING) {
                if (v.type != Value::T_OPCODE && (v.type != Value::T_DATA || v.data.size() != 32)) {
                    printf("warning: ambiguous token '%s' is treated as a value, but could be a variable\n", variable.c_str());
                }
                return refer(std::make_shared<var>(v), true);
            }
            throw std::runtime_error(strprintf("undefined variable: %s", variable.c_str()));
        }
        auto& v = ctx->vars.at(variable);
        if (v->pref) return v->pref;
        if (ctx->mod.get() && v->data.type == Value::T_DATA) {
            auto n = secp256k1::num(v->data.to_string());
            auto m = secp256k1::num(ctx->mod->data.to_string());
            if (n >= m) {
                n = n % m;
                Value mv(ParseHex(n.to_string()));
                v = std::make_shared<var>(mv);
            }
        }
        return refer(v, true);
    }
    inline std::shared_ptr<var>& pull(tiny::ref r) {
        for (;;) {
            std::shared_ptr<var> v = ctx->temps[r];
            if (v->pref && v->pref != r) { r = v->pref; continue; }
            return ctx->temps[r];
        }
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
    tiny::ref push_arr(const std::vector<std::shared_ptr<var>>& arr) {
        tiny::ref pos = ctx->temps.size();
        ctx->temps.push_back(std::make_shared<var>(pos));
        ctx->arrays[pos] = arr;
        return pos;
    }
    tiny::ref bin(tiny::token_type op, std::shared_ptr<var>& l, std::shared_ptr<var>& r) {
        std::shared_ptr<var> tmp;
        switch (op) {
        case tiny::tok_plus:   tmp = l->add(*r); break;
        case tiny::tok_minus:  tmp = l->sub(*r); break;
        case tiny::tok_mul:    tmp = l->mul(*r); break;
        case tiny::tok_div:    tmp = l->div(*r); break;
        case tiny::tok_concat: tmp = l->concat(*r); break;
        case tiny::tok_land:   tmp = l->land(*r); break;
        case tiny::tok_lor:    tmp = l->lor(*r); break;
        // case tiny::tok_lxor:   tmp = l->lxor(*r); break;
        case tiny::tok_pow:    tmp = l->pow(*r); break;
        default: throw std::runtime_error(strprintf("invalid binary operation (%s)", tiny::token_type_str[op]));
        }
        ctx->temps.push_back(tmp);
        return ctx->temps.size() - 1;
    }
    tiny::ref bin(tiny::token_type op, std::shared_ptr<var>& l, tiny::ref rhs) {
        ARRTHRU(rhs, bin(op, l, v));
        // if (ctx->arrays.count(rhs)) {
        //     auto& arr = ctx->arrays.at(rhs);
        //     std::vector<std::shared_ptr<var>> res;
        //     for (auto& v : arr) {
        //         res.push_back(pull(bin(op, l, v)));
        //     }
        //     return push_arr(res);
        // }
        auto r = pull(rhs);
        if (!r) throw std::runtime_error(strprintf("undefined reference %zu (RHS)", rhs));
        return bin(op, l, r);
    }
    tiny::ref bin(tiny::token_type op, tiny::ref lhs, std::shared_ptr<var>& r) {
        ARRTHRU(lhs, bin(op, v, r));
        // if (ctx->arrays.count(lhs)) {
        //     auto& arr = ctx->arrays.at(lhs);
        //     std::vector<std::shared_ptr<var>> res;
        //     for (auto& v : arr) {
        //         res.push_back(pull(bin(op, v, r)));
        //     }
        //     return push_arr(res);
        // }
        auto l = pull(lhs);
        if (!l) throw std::runtime_error(strprintf("undefined reference %zu (LHS)", lhs));
        return bin(op, l, r);
    }
    tiny::ref bin(tiny::token_type op, tiny::ref lhs, tiny::ref rhs) override {
        if (ctx->arrays.count(lhs) && ctx->arrays.count(rhs)) {
            auto l = ctx->arrays.at(lhs);
            auto r = ctx->arrays.at(rhs);
            std::vector<std::shared_ptr<var>> res;
            if (op == tiny::tok_concat) {
                res = l;
                res.insert(res.end(), r.begin(), r.end());
                return push_arr(res);
            }
            if (ctx->arrays.at(lhs).size() == ctx->arrays.at(rhs).size()) {
                for (size_t i = 0; i < l.size(); ++i) {
                    res.push_back(pull(bin(op, l[i], r[i])));
                }
                return push_arr(res);
            }
        }
        ARRTHRU(lhs, bin(op, v, rhs));
        // if (ctx->arrays.count(lhs)) {
        //     auto& arr = ctx->arrays.at(lhs);
        //     std::vector<std::shared_ptr<var>> res;
        //     for (auto& v : arr) {
        //         res.push_back(pull(bin(op, v, rhs)));
        //     }
        //     return push_arr(res);
        // }
        ARRTHRU(rhs, bin(op, lhs, v));
        // if (ctx->arrays.count(rhs)) {
        //     auto& arr = ctx->arrays.at(rhs);
        //     std::vector<std::shared_ptr<var>> res;
        //     for (auto& v : arr) {
        //         res.push_back(pull(bin(op, lhs, v)));
        //     }
        //     return push_arr(res);
        // }
        return bin(op, pull(lhs), pull(rhs));
    }
    // tiny::ref mod(std::shared_ptr<var>& value, std::shared_ptr<var>& m) {
    // 
    // }
    // tiny::ref mod(tiny::ref value, tiny::ref m) override {
    //     auto mv = pull(m);
    //     ARRTHRU(value, mod(v, mv));
    // 
    // }
    // modulo
    void push_mod(tiny::ref m) override {
        auto v = m ? pull(m) : std::shared_ptr<var>();
        ctx->mod = v;
        ctx->mods.push_back(v);
    }
    void pop_mod() override {
        if (ctx->mods.size() == 0) throw std::runtime_error("unable to pop mod stack (it is empty)");
        ctx->mods.pop_back();
        ctx->mod = ctx->mods.size() ? ctx->mods.back() : std::shared_ptr<var>();
    }
    bool compare(std::shared_ptr<var>& a, std::shared_ptr<var>& b, tiny::token_type op) {
        if (a->pref) {
            if (op != tiny::tok_eq && op != tiny::tok_ne) throw std::runtime_error("invalid comparison type for program comparison (only allows == and !=)");
            return op == tiny::tok_eq ? a->pref == b->pref : a->pref != b->pref;
        }
        int64_t c = 0;
        if (op == tiny::tok_eq) return a->data.to_string() == b->data.to_string();
        if (op == tiny::tok_ne) return a->data.to_string() != b->data.to_string();
        if (a->data.type == Value::T_STRING) throw std::runtime_error("cannot compare strings in that fashion");
        if (a->data.type != b->data.type) {
            a->data.data_value();
            b->data.data_value();
        }
        if (a->data.type == Value::T_INT) c = a->data.int64 - b->data.int64;
        else c = memcmp(a->data.data.data(), b->data.data.data(), std::min<size_t>(a->data.data.size(), b->data.data.size()));
        switch (op) {
        case tiny::tok_lt: return c < 0;
        case tiny::tok_gt: return c > 0;
        case tiny::tok_le: return c <= 0;
        case tiny::tok_ge: return c >= 0;
        default: return false;
        }
    }
    tiny::ref compare(tiny::ref a, tiny::ref b, tiny::token_type op) override {
        if (ctx->arrays.count(a)) {
            if (ctx->arrays.count(b) == 0) throw std::runtime_error("cannot mix arrays and non-arrays in comparison operator");
            auto aarr = ctx->arrays[a];
            auto barr = ctx->arrays[b];
            if (aarr.size() != barr.size()) throw std::runtime_error(strprintf("cannot compare arrays of different lengths (%zu vs %zu)", aarr.size(), barr.size()));
            for (size_t i = 0; i < aarr.size(); ++i) {
                if (!compare(aarr[i], barr[i], op)) return _false;
            }
            return _true;
        }
        return compare(pull(a), pull(b), op) ? _true : _false;
    }
    tiny::ref unary(tiny::token_type op, tiny::ref val) override {
        std::shared_ptr<var> v;
        Value z((int64_t)0);
        switch (op) {
        case tiny::tok_not:
            if (ctx->arrays.count(val)) {
                std::vector<std::shared_ptr<var>> res;
                for (auto& e : ctx->arrays.at(val)) {
                    z = Value(e->data);
                    z.do_not_op();
                    res.emplace_back(z.int64 ? env_true : env_false);
                }
                return push_arr(res);
            }
            if (ctx->programs.count(val)) return _true;
            v = pull(val);
            z = Value(v->data);
            z.do_not_op();
            return z.int64 ? _true : _false;
        case tiny::tok_minus:
            ARRTHRU(val, refer(v->negate()));
            if (ctx->programs.count(val)) throw std::runtime_error("cannot negate a program");
            v = pull(val);
            return refer(v->negate(), true);
        default: break;
        }
        throw std::runtime_error("not implemented");
    }
    bool truthy(tiny::ref v) override {
        return unary(tiny::tok_not, v) == _false;
    }
    tiny::ref fcall(const std::string& fname, tiny::ref args) override {
        if (ctx->vars.count(fname)) {
            // potential redirect to internal function
            auto& v = ctx->vars[fname];
            if (v->internal_function) return fcall(v->data.str, args);
        }
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
            return refer(tmp);
        } else return 0;
    }
    tiny::ref transfer(tiny::ref r) {
        // TODO: it may be worth it to simply set the ctx to the destination value and use the
        // TODO: existing functions, with an additional context argument in the call to transfer
        // TODO: for 'source'
        if (!r) return r;
        assert(contexts.size() > 1);
        auto& dst = contexts.at(contexts.size() - 2);
        auto& src = *ctx;
        auto& v = pull(r);
        std::vector<std::shared_ptr<var>> rva;
        tiny::program_t* prog = src.programs.count(r) ? src.programs.at(r) : nullptr;
        if (prog) {
            auto it = std::find(src.owned_programs.begin(), src.owned_programs.end(), prog);
            if (it != src.owned_programs.end()) {
                src.owned_programs.erase(it);
            }
            tiny::ref tr = dst.temps.size();
            dst.temps.push_back(std::make_shared<var>((tiny::ref)tr));
            dst.programs[tr] = prog;
            dst.owned_programs.push_back(prog);
            return tr;
        }
        if (src.arrays.count(r)) {
            std::vector<std::shared_ptr<var>> tarr;
            for (auto& e : src.arrays.at(r)) {
                tarr.push_back(dst.temps[transfer(refer(e))]);
            }
            tiny::ref tr = dst.temps.size();
            dst.temps.push_back(std::make_shared<var>(tr));
            dst.arrays[tr] = tarr;
            return tr;
        }
        dst.temps.push_back(v);
        return dst.temps.size() - 1;
    }
    tiny::ref _call(tiny::program_t* p, const std::vector<std::shared_ptr<var>>& a, const std::string& pname = "<anonymous function>") {
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
        // transfer
        rv = transfer(rv);
        // if (rv == tiny::nullref) {
        //     ctx->teardown();
        //     contexts.pop_back();
        //     ctx = &contexts.back();
        //     return rv;
        // }
        // std::shared_ptr<var> rvp = pull(rv);
        // std::vector<std::shared_ptr<var>> rva;
        // tiny::program_t* prog = ctx->programs.count(rv) ? ctx->programs.at(rv) : nullptr;
        // if (prog) {
        //     auto it = std::find(ctx->owned_programs.begin(), ctx->owned_programs.end(), prog);
        //     if (it != ctx->owned_programs.end()) {
        //         ctx->owned_programs.erase(it);
        //     }
        // }
        // if (ctx->arrays.count(rv)) {
        //     rva = ctx->arrays.at(rv);
        // }
        ctx->teardown();
        contexts.pop_back();
        ctx = &contexts.back();
        // if (rva.size()) {
        //     return push_arr(rva);
        // } else if (prog) {
        //     return preg(prog);
        // } else {
        //     ctx->temps.push_back(rvp);
        //     return ctx->temps.size() - 1;
        // }
        return rv;
    }
    tiny::ref pcall(tiny::ref program, tiny::ref args) override {
        if (ctx->arrays.count(program)) {
            // calling an array of programs, presumably
            std::vector<std::shared_ptr<var>> res;
            // note that ctx will jump around for each pcall so we cannot rely on iterators
            for (size_t i = 0; i < ctx->arrays[program].size(); ++i) {
                auto v = ctx->arrays[program][i];
                if (v->internal_function) {
                    res.push_back(pull(fcall(v->data.str, args)));
                } else {
                    if (!v->pref) throw std::runtime_error("item in array is not a program");
                    res.push_back(pull(pcall(v->pref, args)));
                }
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
        return _call(p, a, pname);
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
        auto tmp = std::make_shared<var>(v, v.is_pubkey());
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
    inline int64_t range_chk(int64_t i, int64_t len) {
        if (i < -len) throw std::runtime_error(strprintf("index out of bounds (%ld < %ld)", (long)i, (long)-len));
        if (i >= len) throw std::runtime_error(strprintf("index out of bounds (%ld > %ld)", (long)i, (long)len - 1));
        if (i < 0) i = len + i;
        return i;
    }
    tiny::ref arr_at(tiny::ref arrayref, int64_t i) {
        auto arr = ctx->arrays.at(arrayref);
        i = range_chk(i, arr.size());
        return refer(arr[i]);
    }
    tiny::ref at(tiny::ref ref, tiny::ref indexref) override {
        auto index = pull(indexref);
        int64_t i = index->data.int_value();
        if (ctx->arrays.count(ref) > 0) return arr_at(ref, i);
        Value r((int64_t)0);
        auto& v = pull(ref);
        switch (v->data.type) {
        case Value::T_STRING:
            i = range_chk(i, v->data.str.length());
            r.type = Value::T_STRING;
            r.str = v->data.str.substr(i, 1);
            break;
        case Value::T_DATA:
            i = range_chk(i, v->data.data.size());
            r.type = Value::T_DATA;
            r.data.resize(1);
            r.data[0] = v->data.data[i];
            break;
        default:
            // this also includes opcodes but we consider them to be ints
            throw std::runtime_error("index reference cannot target integers");
        }
        ctx->temps.push_back(std::make_shared<var>(r));
        return ctx->temps.size() - 1;
    }
    tiny::ref arr_range(tiny::ref arrayref, int64_t is, int64_t ie) {
        auto arr = ctx->arrays.at(arrayref);
        is = range_chk(is, arr.size());
        ie = range_chk(ie, arr.size());
        std::vector<std::shared_ptr<var>> res;
        if (is > ie) {
            for (size_t i = ie; i <= is; ++i) {
                res.insert(res.begin(), arr[i]);
            }
        } else {
            for (size_t i = is; i <= ie; ++i) {
                res.push_back(arr[i]);
            }
        }
        return push_arr(res);
    }
    tiny::ref range(tiny::ref ref, tiny::ref startref, tiny::ref endref) override {
        auto istart = pull(startref);
        int64_t is = istart->data.int_value();
        auto iend = pull(endref);
        int64_t ie = iend->data.int_value();
        if (ctx->arrays.count(ref) > 0) return arr_range(ref, is, ie);
        Value r((int64_t)0);
        auto& v = pull(ref);
        switch (v->data.type) {
        case Value::T_STRING:
            is = range_chk(is, v->data.str.length());
            ie = range_chk(ie, v->data.str.length());
            r.type = Value::T_STRING;
            if (is > ie) {
                r.str = v->data.str.substr(ie, 1+is-ie);
                r.do_reverse();
            } else {
                r.str = v->data.str.substr(is, 1+ie-is);
            }
            break;
        case Value::T_DATA:
            is = range_chk(is, v->data.data.size());
            ie = range_chk(ie, v->data.data.size());
            r.type = Value::T_DATA;
            if (is > ie) {
                r.data.clear();
                for (int64_t i = is; i >= ie; --i) {
                    r.data.push_back(v->data.data[i]);
                }
            } else {
                r.data.resize(1 + ie - is);
                memcpy(r.data.data(), &v->data.data[is], 1+ie-is);
            }
            break;
        default:
            // this also includes opcodes but we consider them to be ints
            throw std::runtime_error("range reference cannot target integers");
        }
        ctx->temps.push_back(std::make_shared<var>(r));
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
    void printvar_(tiny::ref vref) {
        if (ctx->programs.count(vref)) {
            printf("%s", ctx->programs.at(vref)->to_string().c_str());
            return;
        }
        if (ctx->arrays.count(vref)) {
            printf("[");
            bool first = true;
            for (auto& x : ctx->arrays.at(vref)) {
                if (first) first = false; else printf(", ");
                if (x->pref) {
                    printvar_(x->pref);
                } else if (x->internal_function) {
                    printf("[internal]%s", x->data.str.c_str());
                } else {
                    x->data.print();
                }
            }
            printf("]");
            return;
        }
        if (!ctx->temps[vref]) {
            printf("nil");
            return;
        }
        if (ctx->temps[vref]->pref) {
            printvar_(ctx->temps[vref]->pref);
        } else if (ctx->temps[vref]->internal_function) {
            printf("[internal]%s", ctx->temps[vref]->data.str.c_str());
        } else {
            ctx->temps[vref]->data.print();
        }
    }
    void printvar(tiny::ref vref) {
        printvar_(vref);
        printf("\n");
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

extern env_t env;

#endif // included_compiler_env_h_
