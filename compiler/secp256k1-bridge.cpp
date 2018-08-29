// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "secp256k1-bridge.h"
#include <utilstrencodings.h>
#include <tinyformat.h>

#undef HAVE_CONFIG_H
#define USE_NUM_GMP 1

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/src/num_gmp_impl.h>

#define N(n) ((secp256k1_num*)n)

namespace secp256k1 {

num no7("07");

num::~num() {
    if (n) delete (secp256k1_num*) n;
}

num::num() {
    n = new secp256k1_num;
}

num::num(num&& o) {
    n = o.n;
    o.n = nullptr;
}

num::num(const num& o) {
    n = new secp256k1_num;
    secp256k1_num_copy(N(n), N(o.n));
}

num& num::operator=(const num& o) {
    secp256k1_num_copy(N(n), N(o.n));
    return *this;
}

num::num(const std::string& hex) {
    bool neg = false;
    std::vector<uint8_t> bin;
    if (hex[0] == '-') {
        neg = true;
        bin = ParseHex(hex.substr(1));
    } else {
        bin = ParseHex(hex);
    }
    if (bin.size() == 0) throw std::runtime_error(strprintf("invalid hex string: \"%s\"", hex));
    n = new secp256k1_num;
    secp256k1_num_set_bin(N(n), bin.data(), bin.size());
    if (neg) secp256k1_num_negate(N(n));
}

const std::string num::to_string() const {
    size_t sz = secp256k1_num_get_bin_size(N(n));
    unsigned char* buf = new unsigned char[sz];
    secp256k1_num_get_bin(buf, sz, N(n));
    auto rv = HexStr(buf, buf + sz);
    delete [] buf;
    if (is_negative()) rv = "-" + rv;
    return rv;
}

num num::mod_inverse(const num& m) const {
    num rv;
    secp256k1_num_mod_inverse(N(rv.n), N(n), N(m.n));
    return rv;
}

int num::jacobi(const num& b) const {
    return secp256k1_num_jacobi(N(n), N(b.n));
}

int num::compare(const num& o) const {
    return secp256k1_num_cmp(N(n), N(o.n));
}

bool num::operator==(const num& o) const {
    return secp256k1_num_eq(N(n), N(o.n));
}

bool num::operator==(int i) const {
    switch (i) {
    case 0: return secp256k1_num_is_zero(N(n));
    case 1: return secp256k1_num_is_one(N(n));
    default: throw std::runtime_error("invalid operation (int eq operator valid for range [0..1])");
    }
}

num num::operator+(const num& o) const {
    num rv;
    secp256k1_num_add(N(rv.n), N(n), N(o.n));
    return rv;
}

num num::operator-(const num& o) const {
    num rv;
    secp256k1_num_sub(N(rv.n), N(n), N(o.n));
    return rv;
}

num num::operator*(const num& o) const {
    num rv;
    secp256k1_num_mul(N(rv.n), N(n), N(o.n));
    return rv;
}

num num::operator%(const num& m) const {
    num rv(*this);
    secp256k1_num_mod(N(rv.n), N(m.n));
    return rv;
}

num num::operator>>(int bits) const {
    num rv(*this);
    secp256k1_num_shift(N(rv.n), bits);
    return rv;
}

bool num::is_negative() const {
    return secp256k1_num_is_neg(N(n));
}

num num::operator-() const {
    num rv(*this);
    secp256k1_num_negate(N(rv.n));
    return rv;
}

}
