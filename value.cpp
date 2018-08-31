#include <secp256k1.h>

#include <value.h>

#include <support/allocators/secure.h>

#include <uint256.h>
#include <arith_uint256.h>
#include <pubkey.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

void ECC_Start();

#define abort(msg...) do { fprintf(stderr, msg); return; } while (0)

Value Value::prepare_extraction(const Value& a, const Value& b) {
    CScript s;
    s << a.data_value() << b.data_value();
    return Value(s);
}

bool Value::extract_values(std::vector<std::vector<uint8_t>>& values) {
    values.clear();
    CScript s(data.begin(), data.end());
    CScript::const_iterator pc = s.begin();
    opcodetype opcode;
    std::vector<uint8_t> vch;
    while (pc != s.end()) {
        if (!s.GetOp(pc, opcode, vch)) return false;
        if (vch.size() == 0) return false; // we only allow push operations here
        values.push_back(vch);
    }
    return true;
}

void Value::do_verify_sig() {
    // the value is a script-style push of the sighash, pubkey, and signature
    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 3) abort("invalid input (needs a sighash, a pubkey, and a signature)\n");
    if (args[0].size() != 32) abort("invalid input (sighash must be 32 bytes)\n");
    const uint256 sighash(args[0]);
    CPubKey pubkey(args[1]);
    if (!pubkey.IsValid()) abort("invalid pubkey\n");
    int64 = pubkey.Verify(sighash, args[2]);
    type = T_INT;
}

bool Value::is_pubkey() {
    if (type != T_DATA) return false;
    if (!secp256k1_context_sign) ECC_Start();
    return CPubKey(data).IsValid();
}

void Value::do_combine_pubkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two pubkeys)\n");
    CPubKey pubkey1(args[0]);
    CPubKey pubkey2(args[1]);
    if (!pubkey1.IsValid()) abort("invalid pubkey (first)\n");
    if (!pubkey2.IsValid()) abort("invalid pubkey (second)\n");

    const secp256k1_pubkey* d[2];
    secp256k1_pubkey pks[2];
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pks[0], &pubkey1[0], pubkey1.size())) {
        abort("failed to parse pubkey 1\n");
    }
    d[0] = &pks[0];
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pks[1], &pubkey2[0], pubkey2.size())) {
        abort("failed to parse pubkey 2\n");
    }
    d[1] = &pks[1];
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_sign, &result, d, 2)) {
        abort("failed to combine pubkeys\n");
    }
    data.resize(33);
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, data.data(), &publen, &result, SECP256K1_EC_COMPRESSED);
}

void Value::do_tweak_pubkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs a 32 byte value and a public key)\n");
    auto tweak = args[0];
    CPubKey pubkey1(args[1]);
    if (tweak.size() != 32) abort("invalid tweak value (32 byte value required)");
    if (!pubkey1.IsValid()) abort("invalid pubkey");
    secp256k1_pubkey pk1;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk1, &pubkey1[0], pubkey1.size())) {
        abort("failed to parse pubkey\n");
    }

    if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_context_sign, &pk1, tweak.data())) {
        abort("tweak was out of range (chance of around 1 in 2^128 for uniformly random 32-byte arrays, or equal to zero");
    }

    data.resize(33);
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, data.data(), &publen, &pk1, SECP256K1_EC_COMPRESSED);
}

void Value::do_negate_pubkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    CPubKey pubkey(data);
    if (!pubkey.IsValid()) abort("invalid pubkey");
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk, &pubkey[0], pubkey.size())) {
        abort("failed to parse pubkey\n");
    }

    if (!secp256k1_ec_pubkey_negate(secp256k1_context_sign, &pk)) {
        abort("failed to negate pubkey");
    }

    data.resize(33);
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, data.data(), &publen, &pk, SECP256K1_EC_COMPRESSED);
}

Value Value::from_secp256k1_pubkey(const void* secp256k1_pubkey_ptr) {
    if (!secp256k1_context_sign) ECC_Start();

    size_t clen = CPubKey::PUBLIC_KEY_SIZE;
    CPubKey result;
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, (const secp256k1_pubkey *)secp256k1_pubkey_ptr, SECP256K1_EC_COMPRESSED);
    assert(result.size() == clen);
    assert(result.IsValid());
    return Value(std::vector<uint8_t>(result.begin(), result.end()));
}

inline bool get_arith_uint256(const Value& v, arith_uint256& a) {
    switch (v.type) {
    case Value::T_INT:
        a = arith_uint256(v.int64);
        return true;
    case Value::T_DATA:
        {
            uint256 tmp;
            memcpy(tmp.begin(), v.data.data(), std::min<size_t>(32, v.data.size()));
            a = UintToArith256(tmp);
        }
        return true;
    case Value::T_OPCODE:
        fprintf(stderr, "invalid type: opcode\n");
        return false;
    case Value::T_STRING:
        fprintf(stderr, "invalid type: string\n");
    }
    return false;
}

inline void add(std::vector<uint8_t>& data, arith_uint256 a, arith_uint256 b, arith_uint256 g) {
    arith_uint256 c = a + b;
    if (!g.EqualTo(0) && (c >= g || c < a)) {
        // left case is trivial. right case:
        // g = 0xffe
        // a = 0xffd
        // b = 0x005
        // c  = a + b = 0x002
        // c' = a + b modulo g = 0xffd + 0x005 mod 0xffe = 0x004
        // c - g = 0x002 - 0xffe = -0xffc = 0x004
        c -= g;
    }
    uint256 r = ArithToUint256(c);
    data.resize(32);
    memcpy(data.data(), r.begin(), 32);
}

void Value::do_add() {
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() < 2 || args.size() > 3) abort("invalid input (needs two values, with optional group as third)");
    arith_uint256 a, b, g;
    if (!get_arith_uint256(Value(args[0]), a)) return;
    if (!get_arith_uint256(Value(args[1]), b)) return;
    if (args.size() == 3 && !get_arith_uint256(Value(args[2]), g)) return;
    add(data, a, b, g);
}

void Value::do_sub() {
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() < 2 || args.size() > 3) abort("invalid input (needs two values, with optional group as third)");
    arith_uint256 a, b, g;
    if (!get_arith_uint256(Value(args[0]), a)) return;
    if (!get_arith_uint256(Value(args[1]), b)) return;
    if (args.size() == 3 && !get_arith_uint256(Value(args[2]), g)) return;
    b = -b;
    add(data, a, b, g);
}

void Value::do_boolify() {
    std::vector<char> vc;
    int64_t j;
    switch (type) {
    case T_INT:
        return;
    case T_DATA:
        type = T_INT;
        for (auto& v : data) if (v) { int64 = true; return; }
        int64 = false;
        return;
    case T_STRING:
        type = T_INT;
        int64 = str.length() > 0;
        return;
    case T_OPCODE:
        type = T_INT;
        int64 = opcode == OP_TRUE;
        return;
    }
}

void Value::do_not_op() {
    do_boolify();
    int64 = !int64;
}

#ifdef ENABLE_DANGEROUS

void Value::do_combine_privkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two privkeys)\n");
    for (int i = 0; i < 2; i++) {
        if (args[i].size() != 32) {
            // it is probably a WIF encoded key
            Value wif(args[i]);
            wif.str_value();
            if (wif.str.length() != args[i].size()) abort("invalid input to combine_privkeys (private key %d must be 32 byte data or a WIF encoded privkey)\n", i);
            wif.do_decode_wif();
            args[i] = wif.data;
        }
    }

    if (!secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add\n");
    }

    data = args[0];
}

void Value::do_multiply_privkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two privkeys)\n");
    for (int i = 0; i < 2; i++) {
        if (args[i].size() != 32) {
            // it is probably a WIF encoded key
            Value wif(args[i]);
            wif.str_value();
            if (wif.str.length() != args[i].size()) abort("invalid input to multiply_privkeys (private key %d must be 32 byte data or a WIF encoded privkey)\n", i);
            wif.do_decode_wif();
            args[i] = wif.data;
        }
    }

    if (!secp256k1_ec_privkey_tweak_mul(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add\n");
    }

    data = args[0];
}

void Value::do_pow_privkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two privkeys)\n");
    for (int i = 0; i < 2; i++) {
        if (args[i].size() != 32) {
            // it is probably a WIF encoded key
            Value wif(args[i]);
            wif.str_value();
            if (wif.str.length() != args[i].size()) {
                if (i == 0) abort("invalid input to do_pow_privkey (private key %d must be 32 byte data or a WIF encoded privkey)\n", i);
                // we are lenient about item 2; it can be anything
                std::vector<uint8_t>& a = args[1];
                while (a.size() < 32) a.insert(a.begin(), 0);
            } else {
                wif.do_decode_wif();
                args[i] = wif.data;
            }
        }
    }

    if (!secp256k1_ec_privkey_tweak_pow(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_pow\n");
    }

    data = args[0];
}

void Value::do_negate_privkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)\n");

    if (!secp256k1_ec_privkey_negate(secp256k1_context_sign, &data[0])) {
        abort("failed to negate privkey");
    }
}

void Value::do_get_pubkey() {
    if (!secp256k1_context_sign) ECC_Start();

    // the value is a private key or a WIF encoded key
    if (type == T_STRING) {
        do_decode_wif();
    }
    secp256k1_pubkey pubkey;
    size_t clen = CPubKey::PUBLIC_KEY_SIZE;
    CPubKey result;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, data.data());
    assert(ret);
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(result.size() == clen);
    assert(result.IsValid());
    data = std::vector<uint8_t>(result.begin(), result.end());
}

void Value::do_sign() {
    if (!secp256k1_context_sign) ECC_Start();

    // the value is a script-style push of the sighash followed by the private key
    if (type != T_DATA) abort("invalid type (must be data)\n");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs a sighash and a private key)\n");
    if (args[0].size() != 32) {
        // it is probably a WIF encoded key
        Value wif(args[0]);
        wif.str_value();
        if (wif.str.length() != args[0].size()) abort("invalid input (private key must be 32 byte data or a WIF encoded privkey)\n");
        wif.do_decode_wif();
        args[0] = wif.data;
    }
    if (args[0].size() != 32) abort("invalid input (private key must be 32 bytes)\n");
    data = args[0];
    if (args[1].size() != 32) abort("invalid input (sighash must be 32 bytes)\n");
    const uint256 sighash(args[1]);

    std::vector<uint8_t> sigdata;
    size_t siglen = CPubKey::SIGNATURE_SIZE;
    sigdata.resize(siglen);
    uint8_t extra_entropy[32] = {0};
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, sighash.begin(), data.data(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)sigdata.data(), &siglen, &sig);
    sigdata.resize(siglen);
    data = sigdata;
}

#endif // ENABLE_DANGEROUS

void GetRandBytes(unsigned char* buf, int num)
{
    // TODO: Make this more cross platform
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "unable to open /dev/urandom for GetRandBytes(): sorry! btcdeb does not currently work on your operating system for signature signing\n");
        exit(1);
    }
    if (fread(buf, 1, num, f) != num) {
        fprintf(stderr, "unable to read from /dev/urandom\n");
        exit(1);
    }
    fclose(f);
}

void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

void DeserializeBool(const char* bv, std::vector<uint8_t>& output) {
    // big endian, abbreviated downwards, i.e.
    // 0b11 -> 0b00000011 = 3, as opposed to
    // 0b11 -> 0b11000000 = 192
    size_t len = strlen(bv);
    size_t padding = (8 - (len % 8)) % 8;
    size_t shifts = 0;
    uint8_t r = 0;
    for (size_t i = 0; i < len; ++i) {
        bool bit;
        if (padding) {
            bit = false;
            --i;
            --padding;
        } else if (bv[i] == '0') bit = false;
        else if (bv[i] == '1') bit = true;
        else throw std::runtime_error(strprintf("the character '%c' is not allowed in boolean expressions", bv[i]));
        r = (r << 1) | bit;
        shifts++;
        if (shifts > 7) {
            shifts = 0;
            output.push_back(r);
            r = 0;
        }
    }
}

#undef abort
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/src/secp256k1.c>
#include <secp256k1/src/util.h>
#include <secp256k1/src/field_impl.h>
#include <secp256k1/src/group_impl.h>

void Value::calc_point(std::vector<uint8_t>& x, std::vector<uint8_t>& y) {
    CPubKey pubkey(data);
    if (!pubkey.IsValid()) throw std::runtime_error("invalid pubkey");
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk, &pubkey[0], pubkey.size())) {
        throw std::runtime_error("failed to parse pubkey");
    }

    int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey);
    secp256k1_ge ge;
    if (!secp256k1_pubkey_load(secp256k1_context_sign, &ge, &pk)) {
        throw std::runtime_error("failed to load pubkey into group element");
    }

    x.resize(32);
    y.resize(32);
    secp256k1_fe_get_b32(x.data(), &ge.x);
    secp256k1_fe_get_b32(y.data(), &ge.y);
}
