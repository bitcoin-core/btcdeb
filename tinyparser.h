// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_parser_h_
#define included_tiny_parser_h_

namespace tiny {

enum token_type {
    undef,
    symbol,    // variable, function name, ...
    number,
    equal,
    lparen,
    rparen,
    string,
    mul,
    plus,
    minus,
    div,
    concat,
    ws,
};

static const char* token_type_str[] = {
    "???",
    "symbol",
    "number",
    "equal",
    "lparen",
    "rparen",
    "string",
    "mul",
    "plus",
    "minus",
    "div",
    "concat",
    "ws",
};

struct token_t {
    token_type token = undef;
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

inline token_type determine_token(const char c, token_type current) {
    if (c >= '0' && c <= '9') return current == symbol ? symbol : number;
    if (current == number && 
        ((c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F'))) return number; // hexadecimal
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        c == '_') return symbol;
    if (c == '"') return string;
    if (c == '+') return plus;
    if (c == '|') return concat;
    if (c == '-') return minus;
    if (c == '*') return mul;
    if (c == '/') return div;
    if (c == '=') return equal;
    if (c == '(') return lparen;
    if (c == ')') return rparen;
    if (c == ' ' || c == '\t' || c == '\n') return ws;
    return undef;
}

token_t* tokenize(const char* s) {
    token_t* head = nullptr;
    token_t* tail = nullptr;
    bool open = false;
    bool finalized = true;
    char finding = 0;
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
        auto token = determine_token(s[i], tail ? tail->token : undef);
        // if whitespace, close
        open &= (s[i] != ' ' && s[i] != '\t');
        // if open, see if it stays open
        if (open) {
            open = token == tail->token;
        }
        if (!open) {
            if (!finalized) {
                tail->value = strndup(&s[token_start], i-token_start);
                finalized = true;
            }
            switch (token) {
            case string:
                finding = '"';
            case symbol:
            case number:
                finalized = false;
                token_start = i;
                tail = new token_t(token, tail);
                if (!head) head = tail;
                open = true;
                break;
            case equal:
            case lparen:
            case rparen:
            case mul:
            case plus:
            case minus:
            case concat:
            case div:
                tail = new token_t(token, tail);
                tail->value = strndup(&s[i], 1);
                if (!head) head = tail;
                break;
            case ws:
                break;
            case undef:
                throw std::runtime_error(strprintf("tokenization failure at character '%c'", s[i]));
                delete head;
                return nullptr;
            }
        }
    }
    if (!finalized) {
        tail->value = strndup(&s[token_start], i-token_start);
        finalized = true;
    }
    return head;
}

struct st_callback_table {
    virtual void* load(const std::string& variable) = 0;
    virtual void  save(const std::string& variable, void* value) = 0;
    virtual void* bin(token_type op, void* lhs, void* rhs) = 0;
    virtual void* unary(token_type op, void* val) = 0;
    virtual void* fcall(const std::string& fname, int argc, void** argv) = 0;
    virtual void* convert(const std::string& value, token_type type) = 0;
};

struct st_t {
    virtual void print() {
        printf("????");
    }
    virtual void* eval(st_callback_table* ct) {
        return nullptr;
    }
};

struct var_t: public st_t {
    std::string varname;
    var_t(const std::string& varname_in) : varname(varname_in) {}
    void print() override {
        printf("%s", varname.c_str());
    }
    virtual void* eval(st_callback_table* ct) override {
        return ct->load(varname);
    }
};

struct value_t: public st_t {
    token_type type; // number, string, symbol
    std::string value;
    value_t(token_type type_in, const std::string& value_in) : type(type_in), value(value_in) {
        if (type == string) {
            // get rid of quotes
            value = value.substr(1, value.length() - 2);
        }
    }
    void print() override {
        printf("%s:%s", token_type_str[type], value.c_str());
    }
    virtual void* eval(st_callback_table* ct) override {
        return ct->convert(value, type);
    }
};

struct set_t: public st_t {
    std::string varname;
    st_t* value;
    set_t(const std::string& varname_in, st_t* value_in) : varname(varname_in), value(value_in) {}
    void print() override {
        printf("%s = ", varname.c_str());
        value->print();
    }
    virtual void* eval(st_callback_table* ct) override {
        ct->save(varname, value->eval(ct));
        return nullptr;
    }
};

struct call_t: public st_t {
    std::string fname;
    st_t* args;
    call_t(const std::string& fname_in, st_t* args_in) : fname(fname_in), args(args_in) {}
    void print() override {
        printf("%s(", fname.c_str());
        args->print();
        printf(")");
    }
    virtual void* eval(st_callback_table* ct) override {
        void* ca[1];
        ca[0] = args->eval(ct);
        return ct->fcall(fname, 1, ca);
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
        printf("(BIN %s ", token_type_str[op_token]);
        lhs->print();
        printf(" ");
        rhs->print();
        printf(")");
    }
    virtual void* eval(st_callback_table* ct) override {
        return ct->bin(op_token, lhs->eval(ct), rhs->eval(ct));
    }
};

st_t* x;
#define try(parser) x = parser(s); if (x) return x

st_t* parse_variable(token_t** s) {
    if ((*s)->token == symbol) {
        var_t* t = new var_t((*s)->value);
        *s = (*s)->next;
        return t;
    }
    return nullptr;
}

st_t* parse_value(token_t** s) {
    if ((*s)->token == symbol || (*s)->token == number || (*s)->token == string) {
        value_t* t = new value_t((*s)->token, (*s)->value);
        *s = (*s)->next;
        return t;
    }
    return nullptr;
}

st_t* parse_expr(token_t** s, bool allow_binary = true, bool allow_set = false);

st_t* parse_set(token_t** s) {
    // symbol equal [expr]
    token_t* r = *s;
    var_t* var = (var_t*)parse_variable(&r);
    if (!var) return nullptr;
    if (!r || !r->next || r->token != equal) { delete var; return nullptr; }
    r = r->next;
    st_t* val = parse_expr(&r);
    if (!val) { delete var; return nullptr; }
    *s = r;
    st_t* rv = new set_t(var->varname, val);
    delete var;
    return rv;
}

st_t* parse_parenthesized(token_t** s) {
    // lparen expr rparen
    token_t* r = *s;
    if (r->token != lparen || !r->next) return nullptr;
    r = r->next;
    st_t* v = parse_expr(&r);
    if (!v) return nullptr;
    if (!r || r->token != rparen) { delete v; return nullptr; }
    *s = r->next;
    return v;
}

st_t* parse_fcall(token_t** s);
st_t* parse_binary_expr(token_t** s);

st_t* parse_expr(token_t** s, bool allow_binary, bool allow_set) {
    if (allow_binary) { try(parse_binary_expr); }
    if (allow_set) { try(parse_set); }
    try(parse_fcall);
    try(parse_parenthesized);
    try(parse_variable);
    try(parse_value);
    return nullptr;
}

st_t* parse_binary_expr_post_lhs(token_t** s, st_t* lhs) {
    // plus|minus|mul|div [expr]
    token_t* r = *s;
    switch (r->token) {
    case plus:
    case minus:
    case mul:
    case div:
    case concat:
        break;
    default:
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r) return nullptr;
    st_t* rhs = parse_expr(&r);
    if (!rhs) { delete lhs; return nullptr; }
    *s = r;
    return new bin_t(op_token, lhs, rhs);
}

st_t* parse_binary_expr(token_t** s) {
    // [expr] plus|minus|mul|div [expr]
    token_t* r = *s;
    st_t* lhs = parse_expr(&r, false);
    if (!lhs) return nullptr;
    if (!r) { delete lhs; return nullptr; }
    st_t* res = parse_binary_expr_post_lhs(&r, lhs);
    if (!res) return nullptr;
    *s = r;
    return res;
}

st_t* parse_fcall(token_t** s) {
    // symbol lparen arg rparen
    token_t* r = *s;
    if (r->token != symbol) return nullptr;
    std::string fname = r->value;
    r = r->next;
    if (!r || !r->next || r->token != lparen) return nullptr;
    r = r->next;
    st_t* args = parse_expr(&r);
    if (!args) return nullptr;
    // TODO: allow multiple arguments comma separated
    if (!r || r->token != rparen) { delete args; return nullptr; }
    *s = r->next;
    return new call_t(fname, args);
}

st_t* treeify(token_t* tokens) {
    token_t* s = tokens;
    st_t* value = parse_expr(&s, true, true);
    if (s) {
        throw std::runtime_error(strprintf("failed to treeify tokens around token %s", s->value));
        return nullptr;
    }
    return value;
}

} // namespace tiny

#endif // included_tiny_parser_h_
