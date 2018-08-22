// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_parser_h_
#define included_tiny_parser_h_

#include <tinyformat.h>
#include <string.h>
#include <vector>

namespace tiny {

enum token_type {
    tok_undef,
    tok_symbol,    // variable, function name, ...
    tok_number,
    tok_equal,
    tok_exclaim,
    tok_lparen,
    tok_rparen,
    tok_string,
    tok_mul,
    tok_plus,
    tok_minus,
    tok_div,
    tok_concat,
    tok_comma,
    tok_lcurly,
    tok_rcurly,
    tok_semicolon,
    tok_lbracket,
    tok_rbracket,
    tok_hex,
    tok_bin,
    tok_consumable, // consumed by fulfilled token sequences
    tok_ws,
};

static const char* token_type_str[] = {
    "???",
    "symbol",
    "number",
    "equal",
    "exclaim",
    "lparen",
    "rparen",
    "string",
    "*",
    "+",
    "-",
    "/",
    "||",
    ",",
    "lcurly",
    "rcurly",
    "semicolon",
    "lbracket",
    "rbracket",
    "hex",
    "bin",
    "consumable",
    "ws",
};

struct token_t {
    token_type token = tok_undef;
    char* value = nullptr;
    token_t* next = nullptr;
    token_t(token_type token_in, token_t* prev) : token(token_in) {
        if (prev) prev->next = this;
    }
    token_t(token_type token_in, const char* value_in, token_t* prev) :
    token_t(token_in, prev) {
        value = strdup(value_in);
    }
    ~token_t() { if (value) free(value); if (next) delete next; }
    void print() {
        printf("[%s %s]\n", token_type_str[token], value ?: "<null>");
        if (next) next->print();
    }
};

inline token_type determine_token(const char c, const char p, token_type restrict_type, token_type current) {
    if (c == '|') return p == '|' ? tok_concat : tok_consumable;
    if (c == '+') return tok_plus;
    if (c == '-') return tok_minus;
    if (c == '*') return tok_mul;
    if (c == '/') return tok_div;
    if (c == ',') return tok_comma;
    if (c == '=') return tok_equal;
    if (c == '!') return tok_exclaim;
    if (c == ')') return tok_rparen;
    if (c == '}') return tok_rcurly;
    if (c == ']') return tok_rbracket;
    if (c == ';') return tok_semicolon;
    if (c == ' ' || c == '\t' || c == '\n') return tok_ws;
    if (restrict_type != tok_undef) {
        switch (restrict_type) {
        case tok_hex:
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F')) return tok_number;
            break;
        case tok_bin:
            if (c == '0' || c == '1') return tok_number;
            break;
        default: break;
        }
        return tok_undef;
    }

    if (c == 'x' && p == '0' && current == tok_number) return tok_hex;
    if (c == 'b' && p == '0' && current == tok_number) return tok_bin;
    if (c >= '0' && c <= '9') return current == tok_symbol ? tok_symbol : tok_number;
    if (current == tok_number &&
        ((c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F'))) return tok_number; // hexadecimal
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        c == '_') return tok_symbol;
    if (c == '"') return tok_string;
    if (c == '(') return tok_lparen;
    if (c == '{') return tok_lcurly;
    if (c == '[') return tok_lbracket;
    return tok_undef;
}

token_t* tokenize(const char* s);

typedef size_t ref;
static const ref nullref = 0;

class program_t;

struct st_callback_table {
    virtual ref  load(const std::string& variable) = 0;
    virtual void save(const std::string& variable, ref value) = 0;
    virtual ref  bin(token_type op, ref lhs, ref rhs) = 0;
    virtual ref  unary(token_type op, ref val) = 0;
    virtual ref  fcall(const std::string& fname, ref args) = 0;
    virtual ref  pcall(ref program, ref args) = 0;
    virtual ref  preg(program_t* program) = 0;
    virtual ref  convert(const std::string& value, token_type type, token_type restriction) = 0;
    virtual ref  to_array(size_t count, ref* refs) = 0;
    virtual ref  at(ref arrayref, ref indexref) = 0;
    virtual ref  compare(ref a, ref b, bool invert) = 0;
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
};

struct var_t: public st_t {
    std::string varname;
    var_t(const std::string& varname_in) : varname(varname_in) {}
    virtual std::string to_string() override {
        return strprintf("%s", varname);
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->load(varname);
    }
};

struct value_t: public st_t {
    token_type type; // tok_number, tok_string, tok_symbol
    token_type restriction; // tok_hex, tok_bin, tok_undef
    std::string value;
    value_t(token_type type_in, const std::string& value_in, token_type restriction_in) : type(type_in), restriction(restriction_in), value(value_in) {
        if (type == tok_string) {
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
};

struct set_t: public st_t {
    std::string varname;
    st_c value;
    set_t(const std::string& varname_in, st_c value_in) : varname(varname_in), value(value_in) {}
    virtual std::string to_string() override {
        return varname + " = " + value.r->to_string();
    }
    virtual ref eval(st_callback_table* ct) override {
        ref result = value.r->eval(ct);
        ct->save(varname, result);
        return result;
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
        return ct->pcall(pref.r->eval(ct), args->eval(ct));
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
        for (const auto& x : sequence) {
            rv = x.r->eval(ct);
        }
        return rv;
    }
};

class program_t {
private:
    st_c prog;
public:
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
};

struct cmp_t: public st_t {
    bool invert; // !=
    st_t* lhs;
    st_t* rhs;
    cmp_t(bool invert_in, st_t* lhs_in, st_t* rhs_in) : invert(invert_in), lhs(lhs_in), rhs(rhs_in) {}
    ~cmp_t() {
        delete lhs;
        delete rhs;
    }
    virtual std::string to_string() override {
        return "(" + lhs->to_string() + (invert ? " != " : " == ") + rhs->to_string() + ")";
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->compare(lhs->eval(ct), rhs->eval(ct), invert);
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
};

const uint64_t PWS_BIN = 1 << 0;
const uint64_t PWS_SET = 1 << 1;
const uint64_t PWS_PCALL = 1 << 2;
const uint64_t PWS_COMP = 1 << 3;
const uint64_t PWS_AT = 1 << 4;

struct pws {
    uint64_t& flags;
    uint64_t flag;
    token_t* mark = nullptr;
    pws(uint64_t& flags_in, uint64_t flag_in = 0) : flags(flags_in), flag(flag_in) {
        flags |= flag;
    }
    pws(pws& ws, uint64_t flag_in) : pws(ws.flags, flag_in) {}
    ~pws() { flags &= ~flag; }
    inline bool avail(uint64_t flag) { return !(flags & flag); }
};

st_t* parse_variable(pws& ws, token_t** s);
st_t* parse_value(pws& ws, token_t** s, token_type restriction = tok_undef);
st_t* parse_restricted(pws& ws, token_t** s);
st_t* parse_expr(pws& ws_, token_t** s);
st_t* parse_set(pws& ws, token_t** s);
st_t* parse_binset(pws& ws, token_t** s);
st_t* parse_comp(pws& ws, token_t** s);
st_t* parse_parenthesized(pws& ws, token_t** s);
st_t* parse_tok_binary_expr_post_lhs(pws& ws, token_t** s, st_t* lhs);
st_t* parse_tok_binary_expr(pws& ws, token_t** s);
st_t* parse_csv(pws& ws, token_t** s, token_type restricted_type = tok_undef);
st_t* parse_at(pws& ws, token_t** s);
st_t* parse_array(pws& ws, token_t** s);
st_t* parse_pcall(pws& ws, token_t** s);
st_t* parse_fcall(pws& ws, token_t** s);
st_t* parse_sequence(pws& ws, token_t** s);
st_t* parse_preg(pws& ws, token_t** s);

st_t* treeify(token_t* tokens);

} // namespace tiny

#endif // included_tiny_parser_h_
