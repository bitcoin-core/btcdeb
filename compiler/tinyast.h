// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_ast_h_
#define included_tiny_ast_h_

#include <compiler/tinytokenizer.h>

#include <map>

namespace tiny {

typedef size_t ref;
static const ref nullref = 0;

class program_t;

struct st_callback_table {
    bool ret = false;
    virtual ref  load(const std::string& variable) = 0;
    virtual void save(const std::string& variable, ref value) = 0;
    virtual ref  bin(token_type op, ref lhs, ref rhs) = 0;
    // virtual ref  mod(ref v, ref m) = 0;
    virtual ref  unary(token_type op, ref val) = 0;
    virtual ref  fcall(const std::string& fname, ref args) = 0;
    virtual ref  pcall(ref program, ref args) = 0;
    virtual ref  preg(program_t* program) = 0;
    virtual ref  convert(const std::string& value, token_type type, token_type restriction) = 0;
    virtual ref  to_array(size_t count, ref* refs) = 0;
    virtual ref  at(ref arrayref, ref indexref) = 0;
    virtual ref  range(ref arrayref, ref startref, ref endref) = 0;
    virtual ref  compare(ref a, ref b, token_type op) = 0;
    virtual bool truthy(ref v) = 0;
    // modulo
    virtual void push_mod(ref v) = 0;
    virtual void pop_mod() = 0;
};

struct st_t {
    virtual std::string to_string() {
        return "????";
    }
    virtual void print() {
        printf("%s", to_string().c_str());
    }
    virtual ref eval(st_callback_table* ct) {
        return nullref;
    }
    virtual st_t* clone() {
        return new st_t();
    }
    virtual size_t ops() {
        return 1;
    }
};

struct st_c {
    st_t* r;
    size_t* refcnt;
    // void alive() { printf("made st_c with ptr %p ref %zu (%p)\n", r, refcnt ? *refcnt : 0, refcnt); }
    // void dead() { printf("deleting st_c with ptr %p ref %zu (%p)\n", r, refcnt ? *refcnt : 0, refcnt); }
    st_c(st_t* r_in) {
        r = r_in;
        refcnt = (size_t*)malloc(sizeof(size_t));
        *refcnt = 1;
        // alive();
    }
    st_c(const st_c& o) {
        r = o.r;
        refcnt = o.refcnt;
        (*refcnt)++;
        // alive();
    }
    st_c(st_c&& o) {
        r = o.r;
        refcnt = o.refcnt;
        o.r = nullptr;
        o.refcnt = nullptr;
        // alive();
    }
    st_c& operator=(const st_c& o) {
        if (refcnt) {
            if (!--(*refcnt)) {
                // dead();
                delete r;
                delete refcnt;
            }
        }
        r = o.r;
        refcnt = o.refcnt;
        (*refcnt)++;
        // alive();
        return *this;
    }
    ~st_c() {
        // dead();
        if (!refcnt) return;
        if (!--(*refcnt)) {
            delete r;
            delete refcnt;
        }
    }
    st_c clone() {
        return st_c(r->clone());
    }
};

struct var_t: public st_t {
    std::string varname;
    var_t(const std::string& varname_in) : varname(varname_in) {}
    virtual std::string to_string() override {
        return strprintf("'%s", varname);
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->load(varname);
    }
    virtual st_t* clone() override {
        return new var_t(varname);
    }
};

struct value_t: public st_t {
    token_type type; // tok_number, tok_string, tok_symbol
    token_type restriction; // tok_hex, tok_bin, tok_undef
    std::string value;
    value_t(token_type type_in, const std::string& value_in, token_type restriction_in) : type(type_in), restriction(restriction_in), value(value_in) {
        if (type == tok_string && value.length() > 0 && (value[0] == '"' || value[0] == '\'') && value[value.length()-1] == value[0]) {
            // get rid of quotes
            value = value.substr(1, value.length() - 2);
        }
    }
    virtual std::string to_string() override {
        return strprintf("%s", value);
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->convert(value, type, restriction);
    }
    virtual st_t* clone() override {
        return new value_t(type, type == tok_string ? "'" + value + "'" : value, restriction);
    }
};

struct ret_t: public st_t {
    st_c value;
    ret_t(st_c value_in) : value(value_in) {}
    virtual std::string to_string() override {
        return "return " + value.r->to_string();
    }
    virtual ref eval(st_callback_table* ct) override {
        ref result = value.r->eval(ct);
        ct->ret = true;
        return result;
    }
    virtual st_t* clone() override {
        return new ret_t(value.clone());
    }
};

struct set_t: public st_t {
    std::string varname;
    st_c value;
    set_t(const std::string& varname_in, st_c value_in) : varname(varname_in), value(value_in) {}
    virtual std::string to_string() override {
        return "'" + varname + " = " + value.r->to_string();
    }
    virtual ref eval(st_callback_table* ct) override {
        ref result = value.r->eval(ct);
        ct->save(varname, result);
        return result;
    }
    virtual st_t* clone() override {
        return new set_t(varname, value.clone());
    }
};

struct list_t: public st_t {
    ref* listref;
    std::vector<st_c> values;
    list_t(const std::vector<st_c>& values_in) : values(values_in) {
        listref = (ref*)malloc(sizeof(ref) * values.size());
    }
    ~list_t() {
        free(listref);
    }
    virtual std::string to_string() override {
        std::string s = "[";
        for (size_t i = 0; i < values.size(); ++i) {
            s += strprintf("%s", i ? ", " : "") + values[i].r->to_string();
        }
        return s + "]";
    }
    virtual ref eval(st_callback_table* ct) override {
        for (size_t i = 0; i < values.size(); ++i) {
            listref[i] = values[i].r->eval(ct);
        }
        return ct->to_array(values.size(), listref);
    }
    virtual st_t* clone() override {
        std::vector<st_c> cv;
        for (auto& v : values) {
            cv.push_back(v.clone());
        }
        return new list_t(cv);
    }
};

struct at_t: public st_t {
    st_t* array;
    st_t* index;
    at_t(st_t* array_in, st_t* index_in) : array(array_in), index(index_in) {}
    ~at_t() {
        delete array;
        delete index;
    }
    virtual std::string to_string() override {
        return array->to_string() + "[" + index->to_string() + "]";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->at(array->eval(ct), index->eval(ct));
    }
    virtual st_t* clone() override {
        return new at_t(array->clone(), index->clone());
    }
};

struct range_t: public st_t {
    st_t* array;
    st_t* index_begin;
    st_t* index_end;
    range_t(st_t* array_in, st_t* index_begin_in, st_t* index_end_in) : array(array_in), index_begin(index_begin_in), index_end(index_end_in) {}
    ~range_t() {
        delete array;
        delete index_begin;
        delete index_end;
    }
    virtual std::string to_string() override {
        return array->to_string() + "[" + index_begin->to_string() + ":" + index_end->to_string() + "]";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->range(array->eval(ct), index_begin->eval(ct), index_end->eval(ct));
    }
    virtual st_t* clone() override {
        return new range_t(array->clone(), index_begin->clone(), index_end->clone());
    }
};

struct call_t: public st_t {
    std::string fname;
    list_t* args;
    call_t(const std::string& fname_in, list_t* args_in) : fname(fname_in), args(args_in) {}
    ~call_t() {
        delete args;
    }
    virtual std::string to_string() override {
        return fname + "(" + (args ? args->to_string() : "") + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->fcall(fname, args ? args->eval(ct) : nullref);
    }
    virtual st_t* clone() override {
        return new call_t(fname, args ? (list_t*)args->clone() : nullptr);
    }
};

struct pcall_t: public st_t {
    st_c pref;
    list_t* args;
    pcall_t(st_t* pref_in, list_t* args_in) : pref(pref_in), args(args_in) {}
    ~pcall_t() {
        delete args;
    }
    virtual std::string to_string() override {
        return std::string("@") + pref.r->to_string() + "(" + args->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->pcall(pref.r->eval(ct), args ? args->eval(ct) : nullref);
    }
    virtual st_t* clone() override {
        return new pcall_t(pref.r->clone(), (list_t*)args->clone());
    }
};

struct sequence_t: public st_t {
    std::vector<st_c> sequence;
    sequence_t(const std::vector<st_c>& sequence_in) : sequence(sequence_in) {}
    virtual std::string to_string() override {
        std::string s = std::string("{\n");
        for (const auto& x : sequence) {
            s += "\t" + x.r->to_string() + ";\n";
        }
        return s + "}";
    }
    virtual ref eval(st_callback_table* ct) override {
        ref rv = 0;
        ct->ret = false;
        for (const auto& x : sequence) {
            rv = x.r->eval(ct);
            if (ct->ret) return rv;
        }
        return rv;
    }
    virtual st_t* clone() override {
        std::vector<st_c> c;
        for (auto& v : sequence) {
            c.push_back(v.clone());
        }
        return new sequence_t(c);
    }
    virtual size_t ops() override {
        size_t sz = 0;
        for (auto& op : sequence) sz += op.r->ops();
        return sz;
    }
};

struct program_t {
    st_c prog;
    std::vector<std::string> argnames;
    program_t(const std::vector<std::string>& argnames_in, const st_c& prog_in) : argnames(argnames_in), prog(prog_in) {}
    ref run(st_callback_table* ct) {
        return prog.r->eval(ct);
    }
    std::string to_string() {
        std::string s = "[func](";
        for (const auto& r : argnames) s += strprintf("%s%s", r == argnames[0] ? "" : ", ", r);
        s += ") ";
        return s + prog.r->to_string();
    }
};

struct func_t: public st_t {
    std::vector<std::string> argnames;
    st_c sequence;
    func_t(const std::vector<std::string>& argnames_in, sequence_t* sequence_in)
    : argnames(argnames_in)
    , sequence(sequence_in)
    {}
    virtual std::string to_string() override {
        std::string s = "[func](";
        for (const auto& r : argnames) s += strprintf("%s%s", r == argnames[0] ? "" : ", ", r);
        s += ") ";
        return s + sequence.r->to_string();
    }
    virtual ref eval(st_callback_table* ct) override {
        program_t* program = new program_t(argnames, sequence);
        return ct->preg(program);
    }
    virtual st_t* clone() override {
        return new func_t(argnames, (sequence_t*)sequence.r->clone());
    }
    virtual size_t ops() override {
        return sequence.r->ops();
    }
};

struct cmp_t: public st_t {
    token_type op;
    st_t* lhs;
    st_t* rhs;
    cmp_t(token_type op_in, st_t* lhs_in, st_t* rhs_in) : op(op_in), lhs(lhs_in), rhs(rhs_in) {}
    ~cmp_t() {
        delete lhs;
        delete rhs;
    }
    virtual std::string to_string() override {
        return "(" + lhs->to_string() + " " + token_type_str[op] + " " + rhs->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->compare(lhs->eval(ct), rhs->eval(ct), op);
    }
    virtual st_t* clone() override {
        return new cmp_t(op, lhs->clone(), rhs->clone());
    }
};

struct bin_t: public st_t {
    token_type op_token;
    st_t* lhs;
    st_t* rhs;
    bin_t(token_type op_token_in, st_t* lhs_in, st_t* rhs_in) : op_token(op_token_in), lhs(lhs_in), rhs(rhs_in) {}
    ~bin_t() {
        delete lhs;
        delete rhs;
    }
    virtual std::string to_string() override {
        return "(" + lhs->to_string() + " " + token_type_str[op_token] + " " + rhs->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->bin(op_token, lhs->eval(ct), rhs->eval(ct));
    }
    virtual st_t* clone() override {
        return new bin_t(op_token, lhs->clone(), rhs->clone());
    }
};

struct mod_t: public st_t {
    st_t* value;
    st_t* modulo;
    mod_t(st_t* value_in, st_t* modulo_in) : value(value_in), modulo(modulo_in) {}
    ~mod_t() {
        delete value;
        delete modulo;
    }
    virtual std::string to_string() override {
        return "(" + value->to_string() + " mod " + modulo->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        
        ct->push_mod(modulo->eval(ct));
        ref rv = value->eval(ct);
        ct->pop_mod();
        return rv;
    }
    virtual st_t* clone() override {
        return new mod_t(value->clone(), modulo->clone());
    }
};

struct unary_t: public st_t {
    token_type op_token;
    st_t* v;
    unary_t(token_type op_token_in, st_t* v_in) : op_token(op_token_in), v(v_in) {}
    ~unary_t() {
        delete v;
    }
    virtual std::string to_string() override {
        return std::string() + token_type_str[op_token] + "(" + v->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->unary(op_token, v->eval(ct));
    }
    virtual st_t* clone() override {
        return new unary_t(op_token, v->clone());
    }
    virtual size_t ops() override {
        return v->ops();
    }
};

struct if_t: public st_t {
    st_t* condition;
    st_t* iftrue;
    st_t* iffalse;
    if_t(st_t* condition_in, st_t* iftrue_in, st_t* iffalse_in) : condition(condition_in), iftrue(iftrue_in), iffalse(iffalse_in) {}
    ~if_t() {
        delete condition;
        if (iftrue) delete iftrue;
        if (iffalse) delete iffalse;
    }
    virtual std::string to_string() override {
        return "if (" + condition->to_string() + ") " + iftrue->to_string() + (iffalse ? " else " + iffalse->to_string() : "");
    }
    virtual ref eval(st_callback_table* ct) override {
        if (ct->truthy(condition->eval(ct))) {
            return iftrue ? iftrue->eval(ct) : nullref;
        }
        return iffalse ? iffalse->eval(ct) : nullref;
    }
    virtual st_t* clone() override {
        return new if_t(condition->clone(), iftrue ? iftrue->clone() : nullptr, iffalse ? iffalse->clone() : nullptr);
    }
    virtual size_t ops() override {
        return (iftrue ? iftrue->ops() : 0) + (iffalse ? iffalse->ops() : 0);
    }
};

} // namespace tiny

#endif // included_tiny_ast_h_
