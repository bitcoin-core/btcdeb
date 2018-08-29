// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_secp256k1_bridge_h_
#define included_secp256k1_bridge_h_

#include <string>

namespace secp256k1 {

class num {
protected:
    void* n;
public:
    num();
    num(num&& o);
    num(const num& o);
    num& operator=(const num& o);
    num(const std::string& hex);
    ~num();

    const std::string to_string() const;

    /** Compute a modular inverse. The input must be less than the modulus. */
    num mod_inverse(const num& m) const;
    /** Compute the jacobi symbol (this|b). b must be positive and odd. */
    int jacobi(const num& b) const;
    /** Compare to o, and return -1 if this is less, 0 if equal, and 1 if greater. */
    int compare(const num& o) const;

    bool operator==(const num& o) const;
    bool operator==(int i) const;
    bool operator>(const num& o) const { return compare(o) > 0; }
    bool operator<(const num& o) const { return compare(o) < 0; }
    bool operator>=(const num& o) const { return compare(o) >= 0; }
    bool operator<=(const num& o) const { return compare(o) <= 0; }
    num operator+(const num& o) const;
    num operator-(const num& o) const;
    num operator*(const num& o) const;
    num operator%(const num& m) const;
    num operator>>(int bits) const;
    bool is_negative() const;
    num operator-() const;

    template <typename T> inline bool operator!=(const T& o) const { return !operator==(o); }
};

extern num no7;

} // namespace secp256k1

#endif // included_secp256k1_bridge_h_
