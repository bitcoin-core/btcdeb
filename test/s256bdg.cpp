#include "catch.hpp"

#include "../compiler/secp256k1-bridge.h"

class pnum: public secp256k1::num {
public:
    using num::num;
    void* get_n() const { return n; }
};

TEST_CASE("Bignum", "[s256b-bignum]") {
    SECTION("strings") {
        std::string v( "3e2aefc2b334dd9c6581b0d8dd73b185b41cbc4042e4336450f707c9475e0e5c");
        std::string w( "21295c6eef26b4d1965876d2fb8c5f5e35af4338c3c7f6330d19555ebda83ba2");
        std::string x( "1d019353c40e28cacf293a05e1e752277e6d79077f1c3d3143ddb26a89b5d2ba"); // v-w
        std::string y("-1d019353c40e28cacf293a05e1e752277e6d79077f1c3d3143ddb26a89b5d2ba"); // w-v

        secp256k1::num n(v);
        REQUIRE(v == n.to_string());

        secp256k1::num m(w);
        REQUIRE(w == m.to_string());

        secp256k1::num o(x);
        REQUIRE(x == o.to_string());

        secp256k1::num p = n - m;
        REQUIRE(p == o);
        REQUIRE(p.to_string() == x);

        secp256k1::num q = m - n;
        REQUIRE(q.to_string() == y);
    }

    SECTION("general constructors") {
        {
            // default constructor
            pnum cstr_def;
            // const copy constructor; should copy allocation
            auto allocation = cstr_def.get_n();
            pnum cstr_copy(cstr_def);
            REQUIRE(allocation == cstr_def.get_n());
            REQUIRE(allocation != cstr_copy.get_n());
        }
        {
            pnum cstr_def;
            auto allocation = cstr_def.get_n();
            pnum cstr_set;
            cstr_set = cstr_def;
            REQUIRE(allocation == cstr_def.get_n());
            REQUIRE(allocation != cstr_set.get_n());
        }
    }

    // TODO: mod_inverse
    //     /** Compute a modular inverse. The input must be less than the modulus. */
    //     num mod_inverse(const num& m) const;
    // TODO: jacobi
    //     /** Compute the jacobi symbol (this|b). b must be positive and odd. */
    //     int jacobi(const num& b) const;

    SECTION("comparators") {
        pnum
            a("0000000000000000000000000000000000000000000000000000000000000000")
        ,   b("0000000000000000000000000000000000000000000000000000000000000000")
        ,   c("0000000000000000000000000000000000000000000000000000000000000001")
        ,   d("0100000000000000000000000000000000000000000000000000000000000000");
        REQUIRE(a == b);
        REQUIRE(a != c);
        REQUIRE(a != d);
        REQUIRE(a == 0);
        REQUIRE(b == 0);
        REQUIRE(c == 1);
        REQUIRE(d != 0);
        REQUIRE(d != 1);
        secp256k1::num z("21295c6eef26b4d1965876d2fb8c5f5e35af4338c3c7f6330d19555ebda83ba2");
        z = -z;
        REQUIRE(z.is_negative());
    }

    SECTION("general operators") {
        secp256k1::num
            n0("0000000000000000000000000000000000000000000000000000000000000000")
        ,   n1("0000000000000000000000000000000000000000000000000000000000000001")
        ,   n2("0000000000000000000000000000000000000000000000000000000000000002")
        ,   na("0000000000000000000000000000000000006f95f29fa6fd4cdafcb43b806d3c")
        ,   nb("000000000000000000000000000000000000aef2928472b3640e0a07e11db940")
        ,   nA("bd1c928ad00c68f0336fc5ea29b85e4439126f95f29fa6fd4cdafcb43b806d3c")
        ,   nB("4ef3253d6063299ebe2853fa46837507db8daef2928472b3640e0a07e11db940")
        ,   nF("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        ,   G("ffffffffddddddddffffffffddddddde445123192e953da2402da1730da79c9b")
        ,   n("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        auto n3 = n1 + n2;
        REQUIRE(n3.to_string() == "03");
        auto nFe = nF - n1;
        REQUIRE(nFe.to_string() == "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
        auto nFF1 = nF + n1;
        REQUIRE(nFF1.to_string() == "010000000000000000000000000000000000000000000000000000000000000000");
        auto namulb = na * nb;
        REQUIRE(namulb.to_string() == "4c41a6851e1b24be7e8d63da93e8300bca2b70ac8e235e40cad7ab00");
        auto z = n2 >> 1;
        REQUIRE(z == n1);
        auto nAmulBmodn = (nA * nB) % n;
        REQUIRE(nAmulBmodn.to_string() == "bf47cd7ccc46c36f27fb98b0e12a99d90303dfc567c3ecb9363047d21daeb4dd");
    }
}
