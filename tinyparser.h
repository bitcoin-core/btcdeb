// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_parser_h_
#define included_tiny_parser_h_

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

token_t* tokenize(const char* s) {
    token_t* head = nullptr;
    token_t* tail = nullptr;
    token_t* prev = nullptr;
    bool open = false;
    bool finalized = true;
    char finding = 0;
    token_type restrict_type = tok_undef;
    size_t token_start = 0;
    size_t i;
    for (i = 0; s[i]; ++i) {
        // if we are finding a character, keep reading until we find it
        if (finding) {
            if (s[i] != finding) continue;
            finding = 0;
            open = false;
            continue; // we move one extra step, or "foo" will be read in as "foo
        }
        auto token = determine_token(s[i], i ? s[i-1] : 0, restrict_type, tail ? tail->token : tok_undef);
        // printf("token = %s\n", token_type_str[token]);
        if (token == tok_consumable && tail->token == tok_consumable) {
            throw std::runtime_error(strprintf("tokenization failure at character '%c'", s[i]));
            delete head;
            return nullptr;
        }
        if ((token == tok_hex || token == tok_bin) && tail->token == tok_number) tail->token = tok_consumable;
        // if whitespace, close
        if (token == tok_ws) {
            open = false;
            restrict_type = tok_undef;
        }
        // if open, see if it stays open
        if (open) {
            open = token == tail->token;
            if (!open) restrict_type = tok_undef;
        }
        if (!open) {
            if (tail && tail->token == tok_consumable) {
                if (token == tok_hex || token == tok_bin) {
                    restrict_type = token;
                    delete tail;
                    if (head == tail) head = prev;
                    tail = prev;
                }
            } else if (!finalized) {
                tail->value = strndup(&s[token_start], i-token_start);
                finalized = true;
            }
            switch (token) {
            case tok_string:
                finding = '"';
            case tok_symbol:
            case tok_number:
            case tok_consumable:
                prev = tail;
                finalized = false;
                token_start = i;
                tail = new token_t(token, tail);
                if (!head) head = tail;
                open = true;
                break;
            case tok_equal:
            case tok_exclaim:
            case tok_lparen:
            case tok_rparen:
            case tok_mul:
            case tok_plus:
            case tok_minus:
            case tok_concat:
            case tok_comma:
            case tok_lcurly:
            case tok_rcurly:
            case tok_lbracket:
            case tok_rbracket:
            case tok_semicolon:
            case tok_div:
            case tok_hex:
            case tok_bin:
                if (tail && tail->token == tok_consumable) {
                    delete tail;
                    if (head == tail) head = prev;
                    tail = prev;
                }
                prev = tail;
                tail = new token_t(token, tail);
                tail->value = strndup(&s[i], 1 /* misses 1 char for concat/hex/bin, but irrelevant */);
                if (!head) head = tail;
                break;
            case tok_ws:
                break;
            case tok_undef:
                throw std::runtime_error(strprintf("tokenization failure at character '%c'", s[i]));
                delete head;
                return nullptr;
            }
        }
        // for (auto x = head; x; x = x->next) printf(" %s", token_type_str[x->token]); printf("\n");
    }
    if (!finalized) {
        tail->value = strndup(&s[token_start], i-token_start);
        finalized = true;
    }
    return head;
}

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
    virtual ref  compare(ref a, ref b, bool invert) = 0;
};

struct st_t {
    virtual void print() {
        printf("????");
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
    void print() override {
        printf("%s", varname.c_str());
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
    void print() override {
        printf("%s", value.c_str());
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->convert(value, type, restriction);
    }
};

struct set_t: public st_t {
    std::string varname;
    st_c value;
    set_t(const std::string& varname_in, st_c value_in) : varname(varname_in), value(value_in) {}
    void print() override {
        printf("%s = ", varname.c_str());
        value.r->print();
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
    void print() override {
        printf("[");
        for (size_t i = 0; i < values.size(); ++i) {
            printf("%s", i ? ", " : "");
            values[i].r->print();
        }
        printf("]");
    }
    virtual ref eval(st_callback_table* ct) override {
        for (size_t i = 0; i < values.size(); ++i) {
            listref[i] = values[i].r->eval(ct);
        }
        return ct->to_array(values.size(), listref);
    }
};

struct call_t: public st_t {
    std::string fname;
    list_t* args;
    call_t(const std::string& fname_in, list_t* args_in) : fname(fname_in), args(args_in) {}
    ~call_t() {
        delete args;
    }
    void print() override {
        printf("%s(", fname.c_str());
        args->print();
        printf(")");
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->fcall(fname, args->eval(ct));
    }
};

struct pcall_t: public st_t {
    st_c pref;
    list_t* args;
    pcall_t(st_t* pref_in, list_t* args_in) : pref(pref_in), args(args_in) {}
    ~pcall_t() {
        delete args;
    }
    void print() override {
        printf("@");
        pref.r->print();
        printf("(");
        args->print();
        printf(")");
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->pcall(pref.r->eval(ct), args->eval(ct));
    }
};

struct sequence_t: public st_t {
    std::vector<st_c> sequence;
    sequence_t(const std::vector<st_c>& sequence_in) : sequence(sequence_in) {}
    void print() override {
        printf("{\n");
        for (const auto& x : sequence) {
            printf("\t"); x.r->print(); printf(";\n");
        }
        printf("}");
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
    void print() {
        printf("[func](");
        for (const auto& s : argnames) printf("%s%s", s == argnames[0] ? "" : ", ", s.c_str());
        printf(") ");
        prog.r->print();
    }
};

struct func_t: public st_t {
    std::vector<std::string> argnames;
    st_c sequence;
    func_t(const std::vector<std::string>& argnames_in, sequence_t* sequence_in)
    : argnames(argnames_in)
    , sequence(sequence_in)
    {}
    void print() override {
        printf("[func](");
        for (const auto& s : argnames) printf("%s%s", s == argnames[0] ? "" : ", ", s.c_str());
        printf(") ");
        sequence.r->print();
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
    void print() override {
        printf("(");
        lhs->print();
        printf(" %s ", invert ? "!=" : "==");
        rhs->print();
        printf(")");
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
    void print() override {
        printf("(");
        lhs->print();
        printf(" %s ", token_type_str[op_token]);
        rhs->print();
        printf(")");
    }
    virtual ref eval(st_callback_table* ct) override {
        return ct->bin(op_token, lhs->eval(ct), rhs->eval(ct));
    }
};

const uint64_t PWS_BIN = 1 << 0;
const uint64_t PWS_SET = 1 << 1;
const uint64_t PWS_PCALL = 1 << 2;
const uint64_t PWS_COMP = 1 << 3;

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

st_t* x;
// std::string indent = "";
#define try(parser) /*indent += " ";*/ x = parser(ws, s); /*indent = indent.substr(1);*/ if (x) { /*printf("%sGOT " #parser "\n", indent.c_str());*/ return x; }
#define DEBUG_PARSER(s) //printf("- %s\n", s)
#define CLAIM(flag) pws _pws_instance(ws, flag)

st_t* parse_variable(pws& ws, token_t** s) {
    DEBUG_PARSER("variable");
    if ((*s)->token == tok_symbol) {
        var_t* t = new var_t((*s)->value);
        *s = (*s)->next;
        return t;
    }
    return nullptr;
}

st_t* parse_value(pws& ws, token_t** s, token_type restriction = tok_undef) {
    DEBUG_PARSER("value");
    if ((*s)->token == tok_symbol || (*s)->token == tok_number || (*s)->token == tok_string) {
        value_t* t = new value_t((*s)->token, (*s)->value, restriction);
        *s = (*s)->next;
        return t;
    }
    return nullptr;
}

st_t* parse_restricted(pws& ws, token_t** s) {
    DEBUG_PARSER("restricted");
    if (((*s)->token == tok_hex || (*s)->token == tok_bin)) {
        token_t* r = (*s)->next;
        st_t* t = r ? parse_value(ws, &r, (*s)->token) : nullptr;
        if (!t) {
            if ((*s)->token == tok_hex) {
                // we allow '0x'(null)
                t = new value_t(tok_number, "", (*s)->token);
            } else {
                // we do not allow '0b'(null)
                return nullptr;
            }
        }
        *s = r;
        return t;
    }
    return nullptr;
}

st_t* parse_set(pws& ws, token_t** s);
st_t* parse_binset(pws& ws, token_t** s);
st_t* parse_parenthesized(pws& ws, token_t** s);
st_t* parse_pcall(pws& ws, token_t** s);
st_t* parse_preg(pws& ws, token_t** s);
st_t* parse_fcall(pws& ws, token_t** s);
st_t* parse_tok_binary_expr(pws& ws, token_t** s);
st_t* parse_array(pws& ws, token_t** s);
st_t* parse_comp(pws& ws, token_t** s);

st_t* parse_expr(pws& ws_, token_t** s) {
    DEBUG_PARSER("expr");
    uint64_t flags = 0;
    pws clean(flags);
    clean.mark = *s;
    pws& ws = ws_.mark == *s ? ws_ : clean;
    if (ws.avail(PWS_BIN)) { try(parse_tok_binary_expr); }
    if (ws.avail(PWS_SET)) {
        try(parse_set);
        try(parse_binset);
    }
    if (ws.avail(PWS_COMP)) { try(parse_comp); }
    if (ws.avail(PWS_PCALL)) { try(parse_pcall); }
    try(parse_preg);
    try(parse_fcall);
    try(parse_parenthesized);
    try(parse_array);
    try(parse_variable);
    try(parse_restricted);
    try(parse_value);
    return nullptr;
}

st_t* parse_set(pws& ws, token_t** s) {
    // tok_symbol tok_equal [expr]
    DEBUG_PARSER("set");
    token_t* r = *s;
    var_t* var;
    {
        CLAIM(PWS_SET);
        var = (var_t*)parse_variable(ws, &r);
    }
    if (!var) return nullptr;
    if (!r || !r->next || r->token != tok_equal) { delete var; return nullptr; }
    r = r->next;
    st_t* val = parse_expr(ws, &r);
    if (!val) { delete var; return nullptr; }
    *s = r;
    st_t* rv = new set_t(var->varname, val);
    delete var;
    return rv;
}

st_t* parse_binset(pws& ws, token_t** s) {
    // tok_symbol tok_plus|tok_minus|tok_mul|tok_div|tok_concat tok_equal [expr]
    DEBUG_PARSER("binset");
    token_t* r = *s;
    var_t* var;
    {
        CLAIM(PWS_SET);
        var = (var_t*)parse_variable(ws, &r);
    }
    if (!var) return nullptr;
    if (!r) { delete var; return nullptr; }
    switch (r->token) {
    case tok_plus:
    case tok_minus:
    case tok_mul:
    case tok_div:
    case tok_concat:
        break;
    default:
        delete var;
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r || !r->next || r->token != tok_equal) { delete var; return nullptr; }
    r = r->next;
    st_t* val = parse_expr(ws, &r);
    if (!val) { delete var; return nullptr; }
    *s = r;
    st_t* bin = new bin_t(op_token, var, val);
    st_t* rv = new set_t(var->varname, bin);
    return rv;
}

st_t* parse_comp(pws& ws, token_t** s) {
    // tok_symbol tok_equal [expr]
    DEBUG_PARSER("comp_eq");
    token_t* r = *s;
    st_t* a;
    {
        CLAIM(PWS_COMP);
        a = parse_expr(ws, &r);
    }
    if (!a) return nullptr;
    if (!r || !r->next || (r->token != tok_equal && r->token != tok_exclaim)) { delete a; return nullptr; }
    bool invert = r->token == tok_exclaim;
    r = r->next;
    if (!r || !r->next || r->token != tok_equal) { delete a; return nullptr; }
    r = r->next;
    st_t* b = parse_expr(ws, &r);
    if (!b) { delete a; return nullptr; }
    *s = r;
    st_t* rv = new cmp_t(invert, a, b);
    return rv;
}

st_t* parse_parenthesized(pws& ws, token_t** s) { DEBUG_PARSER("parenthesized");
    // tok_lparen expr tok_rparen
    token_t* r = *s;
    if (r->token != tok_lparen || !r->next) return nullptr;
    r = r->next;
    st_t* v = parse_expr(ws, &r);
    if (!v) return nullptr;
    if (!r || r->token != tok_rparen) { delete v; return nullptr; }
    *s = r->next;
    return v;
}

////////////////////////////////////////////////////////////////////////////////
//
// Binary expression parsing
// a OP b
// Note that rules exist for which order evaluation occurs:
// 1. Parenthesis       (a OP b) OP c
//                      ^^^^^^^^
// 2. Mul div           a * b + c
//                      ^^^^^
// 3. Add sub concat (last)
//
// When processing, the parser goes left to right, but the processing order
// becomes right to left:
// #. Input tokens      Parser state
// 1. a * b + c         --
// 2.   * b + c         binary_expr(LHS=a)
// 3.     b + c         -binary_expr_post_lhs(LHS=a, op_token=tok_mul)
// 4.       + c         --binary_expr(LHS=b)
// 5.         c         ---binary_expr(LHS=b, op_token=tok_plus)
// 6.                   ----variable(c)
// 7.                   --binary_expr(LHS=b, op_token=tok_plus, RHS=c)
// 8.                   binary_expr(LHS=a, op_token=tok_mul, RHS=binary_expression(LHS=b, op_token=tok_plus, RHS=c))
// Since this is WRONG, we need to consider the various priority levels as
// different constructs, with different compatibilities. I.e. a construct
// [expr1] * [expr2]
// must disallow [expr2] from being a binary_expr() with op_token + or -.
//

st_t* parse_tok_binary_expr_post_lhs(pws& ws, token_t** s, st_t* lhs) {
    // tok_plus|tok_minus|tok_mul|tok_div [expr]
    DEBUG_PARSER("tok_binary_expr_post_lhs");
    token_t* r = *s;
    switch (r->token) {
    case tok_plus:
    case tok_minus:
    case tok_concat:
    case tok_mul:
    case tok_div:
        break;
    default:
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r) return nullptr;
    st_t* rhs;
    if (op_token == tok_mul || op_token == tok_div) {
        // prio left hand side, if this expression expands
        token_t* z = r;
        {
            CLAIM(PWS_BIN);
            rhs = parse_expr(ws, &z);
        }
        if (rhs && z) {
            bin_t* tmp = new bin_t(op_token, lhs, rhs);
            bin_t* extension = (bin_t*)parse_tok_binary_expr_post_lhs(ws, &z, tmp);
            if (extension) {
                *s = z;
                return extension;
            }
            tmp->lhs = new st_t(); // don't kill our lhs!
            delete tmp;
        }
    }
    rhs = parse_expr(ws, &r);
    if (!rhs) { delete lhs; return nullptr; }
    *s = r;
    return new bin_t(op_token, lhs, rhs);
}

st_t* parse_tok_binary_expr(pws& ws, token_t** s) {
    // [expr] tok_plus|tok_minus|tok_mul|tok_div [expr]
    DEBUG_PARSER("tok_binary_expr");
    token_t* r = *s;
    st_t* lhs;
    {
        CLAIM(PWS_BIN);
        lhs = parse_expr(ws, &r);
    }
    if (!lhs) return nullptr;
    if (!r) { delete lhs; return nullptr; }
    st_t* res = parse_tok_binary_expr_post_lhs(ws, &r, lhs);
    if (!res) return nullptr;
    *s = r;
    return res;
}

st_t* parse_csv(pws& ws, token_t** s, token_type restricted_type = tok_undef) { DEBUG_PARSER("csv");
    // [expr] [tok_comma [expr] [tok_comma [expr] [...]]
    std::vector<st_c> values;
    token_t* r = *s;

    while (r) {
        st_t* next;
        switch (restricted_type) {
        case tok_undef:  next = parse_expr(ws, &r); break;
        case tok_symbol: next = parse_variable(ws, &r); break;
        default: throw std::runtime_error(strprintf("unsupported restriction type %s", token_type_str[restricted_type]));
        }
        if (!next) break;
        values.emplace_back(next);
        if (!r || r->token != tok_comma) break;
        r = r->next;
    }

    if (values.size() == 0) return nullptr;
    *s = r;

    return new list_t(values);
}

st_t* parse_array(pws& ws, token_t** s) { DEBUG_PARSER("array");
    // lbracket [csv] rbracket
    token_t* r = *s;
    if (!r->next || r->token != tok_lbracket) return nullptr;
    r = r->next;
    list_t* csv = (list_t*)parse_csv(ws, &r);
    if (!csv) return nullptr;
    if (!r || r->token != tok_rbracket) { delete csv; return nullptr; }
    *s = r->next;
    return csv;
}

st_t* parse_pcall(pws& ws, token_t** s) {
    // [expr] tok_lparen [arg1 [tok_comma arg2 [...]]] tok_rparen
    DEBUG_PARSER("pcall");
    token_t* r = *s;
    st_t* pref;
    {
        CLAIM(PWS_PCALL);
        pref = parse_expr(ws, &r);
    }
    if (!pref) return nullptr;
    if (!r || !r->next || r->token != tok_lparen) { delete pref; return nullptr; }
    r = r->next;
    list_t* args = (list_t*)parse_csv(ws, &r); // may be null, for case function() (0 args)
    if (!r) { if (args) delete args; delete pref; return nullptr; }
    if (!r || r->token != tok_rparen) { delete args; delete pref; return nullptr; }
    *s = r->next;
    return new pcall_t(pref, args);
}

st_t* parse_fcall(pws& ws, token_t** s) { DEBUG_PARSER("fcall");
    // tok_symbol tok_lparen [arg1 [tok_comma arg2 [tok_comma arg3 [...]]] tok_rparen
    token_t* r = *s;
    if (r->token != tok_symbol) return nullptr;
    std::string fname = r->value;
    r = r->next;
    if (!r || !r->next || r->token != tok_lparen) return nullptr;
    r = r->next;
    list_t* args = (list_t*)parse_csv(ws, &r); // may be null, for case function() (0 args)
    if (!r) { if (args) delete args; return nullptr; }
    if (!r || r->token != tok_rparen) { delete args; return nullptr; }
    *s = r->next;
    return new call_t(fname, args);
}

st_t* parse_sequence(pws& ws, token_t** s) { DEBUG_PARSER("sequence");
    // lcurly [expr] [semicolon [expr] [...]] rcurly
    token_t* r = *s;
    if (!r->next || r->token != tok_lcurly) return nullptr;
    r = r->next;
    std::vector<st_c> sequence_list;
    while (r && r->token != tok_rcurly) {
        uint64_t flags = 0;
        pws sub_ws(flags);
        st_t* e = parse_expr(sub_ws, &r);
        sequence_list.emplace_back(e);
        if (r && r->token == tok_semicolon) {
            r = r->next;
        } else break;
    }
    if (!r || r->token != tok_rcurly) return nullptr;
    r = r->next;
    *s = r;
    return new sequence_t(sequence_list);
}

st_t* parse_preg(pws& ws, token_t** s) { DEBUG_PARSER("preg");
    // lparen symbol [comma symbol [...]] rparen [sequence]
    token_t* r = *s;
    if (!r->next || r->token != tok_lparen) return nullptr;
    r = r->next;
    list_t* argnames = (list_t*)parse_csv(ws, &r, tok_symbol);
    if (!r || r->token != tok_rparen) {
        if (argnames) delete argnames;
        return nullptr;
    }
    r = r->next;
    sequence_t* prog = (sequence_t*)parse_sequence(ws, &r);
    if (!prog) {
        if (argnames) delete argnames;
        return nullptr;
    }
    std::vector<std::string> an;
    for (const auto& c : argnames->values) {
        an.push_back(((var_t*)c.r)->varname);
    }
    *s = r;
    return new func_t(an, prog);
}

st_t* treeify(token_t* tokens) {
    uint64_t flags = 0;
    pws ws(flags);
    token_t* s = tokens;
    st_t* value = parse_expr(ws, &s);
    if (s) {
        throw std::runtime_error(strprintf("failed to treeify tokens around token %s", s->value));
        return nullptr;
    }
    return value;
}

} // namespace tiny

#endif // included_tiny_parser_h_
