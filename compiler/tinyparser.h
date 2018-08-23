// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_tiny_parser_h_
#define included_tiny_parser_h_

#include <compiler/tinytokenizer.h>
#include <compiler/tinyast.h>

namespace tiny {

const uint64_t PWS_BIN = 1 << 0;
const uint64_t PWS_SET = 1 << 1;
const uint64_t PWS_PCALL = 1 << 2;
const uint64_t PWS_COMP = 1 << 3;
const uint64_t PWS_AT = 1 << 4;
const uint64_t PWS_RANGE = 1 << 5;

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
st_t* parse_range(pws& ws, token_t** s);
st_t* parse_at(pws& ws, token_t** s);
st_t* parse_array(pws& ws, token_t** s);
st_t* parse_pcall(pws& ws, token_t** s);
st_t* parse_fcall(pws& ws, token_t** s);
st_t* parse_sequence(pws& ws, token_t** s);
st_t* parse_preg(pws& ws, token_t** s);

st_t* treeify(token_t* tokens);

} // namespace tiny

#endif // included_tiny_parser_h_
