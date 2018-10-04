// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compiler/tinyparser.h>

namespace tiny {

std::vector<std::string> pdt;
std::string pdts = "";
static size_t ctr = 0;
struct pdo {
    pdo(const std::string& v) {
        pdt.push_back(v);
        ctr++;
        printf("%s%s [%zu] {\n", pdts.c_str(), v.c_str(), ctr);
        pdts += "  ";
    }
    ~pdo() {
        pdts = pdts.substr(2);
        pdt.pop_back();
        if (pdt.size()) printf("%s} // %s\n", pdts.c_str(), pdt.back().c_str());
    }
};

token_t* head = nullptr;
inline size_t count(token_t* head, token_t* t) {
    size_t i = 0;
    for (token_t* q = head; q && q != t; q = q->next) i++;
    return i;
}

// std::string indent = "";
#define try(parser) \
    /*indent += " ";*/ \
    x = parser(ws, s); \
    /*indent = indent.substr(1);*/\
    if (x) {\
        if (ws.pcache.count(pcv)) delete ws.pcache[pcv];\
        ws.pcache[pcv] = new cache(x->clone(), *s);\
        /*printf("#%zu [caching %s=%p(%s, %s)]\n", count(head, *s), x->to_string().c_str(), *s, *s ? token_type_str[(*s)->token] : "<null>", *s ? (*s)->value ?: "<nil>" : "<null>");*/\
        /* printf("GOT " #parser ": %s\n", x->to_string().c_str());*/\
        return x;\
    }
#define DEBUG_PARSER(s) //pdo __pdo(s) //printf("- %s\n", s)
#define CLAIM(flag) ws.mark = r; pws _pws_instance(ws, flag)
#define CLAIM2(flag1, flag2) ws.mark = r; pws _pws_instance(ws, flag1 | flag2)

st_t* parse_expr(pws& ws_, token_t** s) {
    DEBUG_PARSER("expr");
    st_t* x;
    token_t* pcv = *s;
    // printf("parsing #%zu=%s (%s)\n", count(head, pcv), token_type_str[pcv->token], pcv->value ?: "<null>");
    if (ws_.pcache.count(pcv)) return ws_.pcache.at(pcv)->hit(s);

    uint64_t flags = 0;
    pws clean(ws_.pcache, flags);
    clean.mark = *s;
    clean.flags |= ws_.flags & (PWS_LOGICAL | PWS_IF);
    // if (ws_.mark != *s) printf("(clean)\n");
    pws& ws = ws_.mark == *s ? ws_ : clean;
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_IF)) { try(parse_if); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_MOD)) { try(parse_mod); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_LOGICAL)) { try(parse_logical_expr); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_COMP)) { try(parse_comp); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_BIN_LP)) { try(parse_binary_lowpri_expr); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_BIN)) { try(parse_binary_expr); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_SET)) {
        try(parse_set);
        try(parse_binset);
    }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_PCALL)) { try(parse_pcall); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_RANGE)) { try(parse_range); }
    if (!ws_.pcache.count(pcv) && ws.avail(PWS_AT)) { try(parse_at); }
    if (ws_.pcache.count(pcv)) return ws_.pcache.at(pcv)->hit(s);
    try(parse_ret);
    try(parse_unary_expr);
    try(parse_spreg);
    try(parse_preg);
    try(parse_fcall);
    try(parse_parenthesized);
    try(parse_array);
    try(parse_variable);
    try(parse_restricted);
    try(parse_value);
    return nullptr;
}

st_t* parse_variable(pws& ws, token_t** s) {
    DEBUG_PARSER("variable");
    if ((*s)->token == tok_symbol) {
        var_t* t = new var_t((*s)->value);
        *s = (*s)->next;
        return t;
    }
    return nullptr;
}

st_t* parse_value(pws& ws, token_t** s, token_type restriction) {
    DEBUG_PARSER("value");
    // tok_number|tok_symbol|tok_string
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

st_t* parse_set(pws& ws, token_t** s) {
    // tok_symbol tok_set [expr]
    DEBUG_PARSER("set");
    token_t* r = *s;
    var_t* var;
    {
        CLAIM(PWS_SET);
        var = (var_t*)parse_variable(ws, &r);
    }
    if (!var) return nullptr;
    if (!r || !r->next || r->token != tok_set) { delete var; return nullptr; }
    r = r->next;
    st_t* val = parse_expr(ws, &r);
    if (!val) { delete var; return nullptr; }
    *s = r;
    st_t* rv = new set_t(var->varname, val);
    delete var;
    return rv;
}

st_t* parse_ret(pws& ws, token_t** s) {
    // "return" [expr]
    DEBUG_PARSER("ret");
    token_t* r = *s;
    if (r->token != tok_symbol || strcmp(r->value, "return")) return nullptr;
    r = r->next;
    st_t* val = parse_expr(ws, &r);
    if (!val) return nullptr;
    *s = r;
    return new ret_t(val);
}

st_t* parse_binset(pws& ws, token_t** s) {
    // tok_symbol tok_plus|tok_minus|tok_mul|tok_div|tok_concat|tok_pow tok_set [expr]
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
    case tok_pow:
        break;
    default:
        delete var;
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r || !r->next || r->token != tok_set) { delete var; return nullptr; }
    r = r->next;
    st_t* val = parse_expr(ws, &r);
    if (!val) { delete var; return nullptr; }
    *s = r;
    st_t* bin = new bin_t(op_token, var, val);
    st_t* rv = new set_t(var->varname, bin);
    return rv;
}

st_t* parse_comp(pws& ws, token_t** s) {
    // tok_symbol tok_eq|tok_ne|tok_lt|tok_gt|tok_le|tok_ge [expr]
    DEBUG_PARSER("comp_eq");
    token_t* r = *s;
    st_t* a;
    {
        CLAIM(PWS_COMP);
        a = parse_expr(ws, &r);
    }
    if (!a) return nullptr;
    if (!r || !r->next) { delete a; return nullptr; }
    token_type op = r->token;
    switch (r->token) {
    case tok_eq: 
    case tok_ne: 
    case tok_lt: 
    case tok_gt: 
    case tok_le: 
    case tok_ge: break;
    default: delete a; return nullptr;
    }
    r = r->next;
    st_t* b = parse_expr(ws, &r);
    if (!b) { delete a; return nullptr; }
    *s = r;
    st_t* rv = new cmp_t(op, a, b);
    return rv;
}

st_t* parse_parenthesized(pws& ws, token_t** s) {
    // tok_lparen expr tok_rparen
    DEBUG_PARSER("parenthesized");
    token_t* r = *s;
    if (r->token != tok_lparen || !r->next) return nullptr;
    r = r->next;
    st_t* v = parse_expr(ws, &r);
    if (!v) return nullptr;
    if (!r || r->token != tok_rparen) { return nullptr; }
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
// 3. Add sub concat
// 4. And (&&)
// 5. Or, xor (||, ^)
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

st_t* parse_binary_expr_post_lhs(pws& ws, token_t** s, st_t* lhs) {
    // tok_concat|tok_mul|tok_div|pow [expr]
    DEBUG_PARSER("binary_expr_post_lhs");
    token_t* r = *s;
    CLAIM(PWS_LOGICAL);
    switch (r->token) {
    case tok_concat:
    case tok_mul:
    case tok_div:
    case tok_pow:
        break;
    default:
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r) return nullptr;
    st_t* rhs;
    if (op_token == tok_mul || op_token == tok_div || op_token == tok_pow) {
        // prio left hand side, if this expression expands
        token_t* z = r;
        {
            CLAIM(PWS_BIN);
            rhs = parse_expr(ws, &z);
        }
        if (rhs && z) {
            bin_t* tmp = new bin_t(op_token, lhs, rhs);
            bin_t* extension = (bin_t*)parse_binary_expr_post_lhs(ws, &z, tmp);
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

st_t* parse_binary_expr(pws& ws, token_t** s) {
    // [expr] tok_plus|tok_minus|tok_mul|tok_div|tok_pow [expr]
    token_t* r = *s;
    CLAIM(PWS_LOGICAL);
    DEBUG_PARSER("binary_expr");
    st_t* lhs;
    {
        CLAIM(PWS_BIN);
        lhs = parse_expr(ws, &r);
    }
    if (!lhs) return nullptr;
    if (!r) { delete lhs; return nullptr; }
    st_t* res = parse_binary_expr_post_lhs(ws, &r, lhs);
    if (!res) return nullptr;
    *s = r;
    return res;
}

st_t* parse_binary_lowpri_expr_post_lhs(pws& ws, token_t** s, st_t* lhs) {
    // tok_plus|tok_minus [expr]
    DEBUG_PARSER("binary_lowpri_expr_post_lhs");
    token_t* r = *s;
    CLAIM(PWS_LOGICAL);
    switch (r->token) {
    case tok_plus:
    case tok_minus:
        break;
    default:
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r) return nullptr;
    st_t* rhs;
    if (op_token == tok_minus) {
        // prio left hand side, if this expression expands
        token_t* z = r;
        {
            CLAIM(PWS_BIN_LP);
            rhs = parse_expr(ws, &z);
        }
        if (rhs && z) {
            bin_t* tmp = new bin_t(op_token, lhs, rhs);
            bin_t* extension = (bin_t*)parse_binary_lowpri_expr_post_lhs(ws, &z, tmp);
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

st_t* parse_binary_lowpri_expr(pws& ws, token_t** s) {
    // [expr] tok_plus|tok_minus [expr]
    token_t* r = *s;
    CLAIM(PWS_LOGICAL);
    DEBUG_PARSER("binary_lowpri_expr");
    st_t* lhs;
    {
        CLAIM(PWS_BIN_LP);
        lhs = parse_expr(ws, &r);
    }
    if (!lhs) return nullptr;
    if (!r) { delete lhs; return nullptr; }
    st_t* res = parse_binary_lowpri_expr_post_lhs(ws, &r, lhs);
    if (!res) return nullptr;
    *s = r;
    return res;
}

st_t* parse_mod(pws& ws, token_t** s) {
    // [expr] mod [expr]
    DEBUG_PARSER("mod");
    token_t* r = *s;
    st_t* value;
    {
        CLAIM(PWS_MOD);
        value = parse_expr(ws, &r);
    }
    if (!value) return nullptr;
    if (!r || r->token != tok_symbol || strcmp(r->value, "mod")) { delete value; return nullptr; }
    r = r->next;
    st_t* m = parse_expr(ws, &r);
    if (!m) { delete value; return nullptr; }
    *s = r;
    return new mod_t(value, m);
}

st_t* parse_logical_expr_post_lhs(pws& ws, token_t** s, st_t* lhs) {
    // tok_land|tok_lor [expr]
    DEBUG_PARSER("logical_expr_post_lhs");
    token_t* r = *s;
    switch (r->token) {
    case tok_land:
    case tok_lor:
        break;
    default:
        return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    if (!r) return nullptr;
    st_t* rhs;
    if (op_token == tok_land) {
        // prio left hand side, if this expression expands
        token_t* z = r;
        {
            CLAIM(PWS_LOGICAL);
            rhs = parse_expr(ws, &z);
        }
        if (rhs && z) {
            bin_t* tmp = new bin_t(op_token, lhs, rhs);
            bin_t* extension = (bin_t*)parse_logical_expr_post_lhs(ws, &z, tmp);
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

st_t* parse_logical_expr(pws& ws, token_t** s) {
    // [expr] tok_land|tok_lor [expr]
    DEBUG_PARSER("logical_expr");
    token_t* r = *s;
    st_t* lhs;
    {
        CLAIM(PWS_LOGICAL);
        lhs = parse_expr(ws, &r);
    }
    if (!lhs) return nullptr;
    if (!r) { delete lhs; return nullptr; }
    st_t* res = parse_logical_expr_post_lhs(ws, &r, lhs);
    if (!res) return nullptr;
    *s = r;
    return res;
}

st_t* parse_unary_expr(pws& ws, token_t** s) {
    // tok_not|tok_minus [expr]
    DEBUG_PARSER("unary_expr");
    token_t* r = *s;
    if (!r->next) return nullptr;
    switch (r->token) {
    case tok_not:
    case tok_minus: break;
    default: return nullptr;
    }
    token_type op_token = r->token;
    r = r->next;
    // we do not allow e.g. -1 * 38 to mean -(1 * 38) because that means
    // we also allow -1 - 1 to mean -(1 - 1)
    st_t* e;
    {
        CLAIM2(PWS_LOGICAL, PWS_BIN);
        e = parse_expr(ws, &r);
    }
    if (!e) return nullptr;
    *s = r;
    return new unary_t(op_token, e);
}

st_t* parse_csv(pws& ws, token_t** s, token_type restricted_type) {
    // [expr] [tok_comma [expr] [tok_comma [expr] [...]]
    DEBUG_PARSER("csv");
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

st_t* parse_at(pws& ws, token_t** s) {
    // [expr] lbracket [expr] rbracket
    DEBUG_PARSER("at");
    token_t* r = *s;
    st_t* array;
    {
        CLAIM(PWS_AT);
        array = parse_expr(ws, &r);
    }
    if (!array) return nullptr;
    if (!r || !r->next || r->token != tok_lbracket) { delete array; return nullptr; }
    r = r->next;
    st_t* index = parse_expr(ws, &r);
    if (!index) { delete array; return nullptr; }
    if (!r || r->token != tok_rbracket) { delete array; delete index; return nullptr; }
    *s = r->next;
    return new at_t(array, index);
}

st_t* parse_range(pws& ws, token_t** s) {
    // [expr] lbracket [expr] colon [expr] rbracket
    DEBUG_PARSER("range");
    token_t* r = *s;
    st_t* array;
    {
        CLAIM(PWS_RANGE);
        array = parse_expr(ws, &r);
    }
    if (!array) return nullptr;
    if (!r || !r->next || r->token != tok_lbracket) { delete array; return nullptr; }
    r = r->next;
    st_t* index_start = parse_expr(ws, &r);
    if (!index_start) { delete array; return nullptr; }
    if (!r || !r->next || r->token != tok_colon) { delete array; delete index_start; return nullptr; }
    r = r->next;
    st_t* index_end = parse_expr(ws, &r);
    if (!index_end) { delete array; delete index_start; return nullptr; }
    if (!r || r->token != tok_rbracket) { delete array; delete index_start; delete index_end; return nullptr; }
    *s = r->next;
    return new range_t(array, index_start, index_end);
}

st_t* parse_array(pws& ws, token_t** s) {
    // lbracket [csv] rbracket
    DEBUG_PARSER("array");
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

st_t* parse_fcall(pws& ws, token_t** s) {
    // tok_symbol tok_lparen [arg1 [tok_comma arg2 [tok_comma arg3 [...]]] tok_rparen
    DEBUG_PARSER("fcall");
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

st_t* parse_sequence(pws& ws, token_t** s) {
    // lcurly [expr] [semicolon [expr] [...]] rcurly
    DEBUG_PARSER("sequence");
    token_t* r = *s;
    if (!r->next || r->token != tok_lcurly) return nullptr;
    r = r->next;
    std::vector<st_c> sequence_list;
    while (r && r->token != tok_rcurly) {
        uint64_t flags = 0;
        pws sub_ws(ws.pcache, flags);
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

st_t* parse_preg(pws& ws, token_t** s) {
    // lparen symbol [comma symbol [...]] rparen [sequence]
    DEBUG_PARSER("preg");
    token_t* r = *s;
    if (!r->next || r->token != tok_lparen) return nullptr;
    r = r->next;
    list_t* argnames = (list_t*)parse_csv(ws, &r, tok_symbol);
    if (!r || r->token != tok_rparen || !r->next) {
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
    if (argnames) {
        for (const auto& c : argnames->values) {
            an.push_back(((var_t*)c.r)->varname);
        }
    }
    *s = r;
    return new func_t(an, prog);
}

st_t* parse_spreg(pws& ws, token_t** s) {
    // symbol|(lparen symbol [comma symbol [...]] rparen) arrow [expr]
    DEBUG_PARSER("spreg");
    token_t* r = *s;
    list_t* argnames;
    // single symbol followed by arrow:
    //  var                         =>                                       expr
    if (r->token == tok_symbol && r->next && r->next->token == tok_arrow && r->next->next) {
        st_t* v = parse_variable(ws, &r);
        argnames = new list_t(std::vector<st_c>{st_c(v)});
        r = r->next;
    } else {
        if (!r->next || r->token != tok_lparen) return nullptr;
        r = r->next;
        argnames = (list_t*)parse_csv(ws, &r, tok_symbol);
        if (!r || r->token != tok_rparen || !r->next || r->next->token != tok_arrow || !r->next->next) {
            if (argnames) delete argnames;
            return nullptr;
        }
        r = r->next->next;
    }
    sequence_t* prog;
    if (r->token == tok_lcurly) {
        prog = (sequence_t*)parse_sequence(ws, &r);
    } else {
        st_t* p = parse_expr(ws, &r);
        if (!p) {
            if (argnames) delete argnames;
            return nullptr;
        }
        prog = new sequence_t(std::vector<st_c>{st_c(p)});
    }
    if (!prog) {
        if (argnames) delete argnames;
        return nullptr;
    }
    std::vector<std::string> an;
    if (argnames) {
        for (const auto& c : argnames->values) {
            an.push_back(((var_t*)c.r)->varname);
        }
    }
    *s = r;
    return new func_t(an, prog);
}

st_t* parse_if(pws& ws, token_t** s) {
    // if lparen [expr] rparen [expr] ( else [expr] )
    token_t* r = *s;
    CLAIM(PWS_IF);
    if (!r->next || r->token != tok_symbol || strcmp(r->value, "if")) return nullptr;
    r = r->next;
    st_t* condition = parse_expr(ws, &r);
    if (!condition) return nullptr;
    if (!r) { delete condition; return nullptr; }
    st_t* iftrue = r->token == tok_lcurly ? parse_sequence(ws, &r) : parse_expr(ws, &r);
    if (!iftrue) { delete condition; return nullptr; }
    st_t* iffalse = nullptr;
    if (r && r->token == tok_symbol && !strcmp(r->value, "else")) {
        r = r->next;
        iffalse = r->token == tok_lcurly ? parse_sequence(ws, &r) : parse_expr(ws, &r);
    }
    *s = r;
    return new if_t(condition, iftrue, iffalse);
}

st_t* treeify(token_t* tokens) {
    head = tokens;
    cache_t pcache;
    uint64_t flags = 0;
    pws ws(pcache, flags);
    token_t* s = tokens;
    st_t* value = parse_expr(ws, &s);
    head = nullptr;
    if (!s && value) {
        value = value->clone();
    }
    for (auto& v : pcache) delete v.second;
    if (s) {
        throw std::runtime_error(strprintf("failed to treeify tokens around token %s", s->value ?: token_type_str[s->token]));
        return nullptr;
    }
    return value;
}

} // namespace tiny
