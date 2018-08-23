// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_tokenizer_h_
#define included_tiny_tokenizer_h_

#include <tinyformat.h>
#include <string.h>
#include <vector>

namespace tiny {

enum token_type {
    tok_undef,
    tok_symbol,    // variable, function name, ...
    tok_number,
    tok_equal,
    tok_lt,
    tok_gt,
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
    "<",
    ">",
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
    if (c == '<') return tok_lt;
    if (c == '>') return tok_gt;
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

} // namespace tiny

#endif // included_tiny_tokenizer_h_
