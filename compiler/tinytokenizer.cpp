// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compiler/tinytokenizer.h>

namespace tiny {

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
            case tok_lt:
            case tok_gt:
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
            case tok_colon:
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

} // namespace tiny
