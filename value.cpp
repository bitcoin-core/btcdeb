#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_recovery.h>

#include <value.h>

#include <support/allocators/secure.h>

#include <uint256.h>
#include <arith_uint256.h>
#include <pubkey.h>

const uint256 SECP256K1_FIELD_SIZE = uint256S("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

secp256k1_context* secp256k1_context_sign = nullptr;

void ECC_Start();

std::string bech32_hrp = "bcrt";
uint8_t bech32_witness_version = 1;

#define abort(msg...) do { fprintf(stderr, msg); fputc('\n', stderr); return; } while (0)

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

void Value::verify_sig(bool compact) {
    // the value is a script-style push of the sighash, pubkey, and signature
    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 3) abort("invalid input (needs a sighash, a pubkey, and a signature)");
    if (args[0].size() != 32 && args[0].size() != 64) abort("invalid input (sighash must be 32 or 64 bytes)");
    const uint256 sighash(args[0]);

    if (args[1].size() == 32) {
        // new style pubkey, so use schnorr validation
        XOnlyPubKey pubkey((uint256(args[1])));
        if (!pubkey.IsValid()) abort("invalid x only pubkey");
        int64 = pubkey.VerifySchnorr(sighash, args[2]);
        if (int64 == 0) {
            uint256 sh2;
            for (int i = 0; i < 32; ++i) sh2.begin()[i] = sighash.begin()[31-i];
            if (pubkey.VerifySchnorr(sh2, args[2])) {
                fprintf(stderr, "NOTE: your sighash is probably in reverse order (validation succeeds for flipped sighash)\n");
            } else {
                uint256 pk2;
                for (int i = 0; i < 32; ++i) pk2.begin()[i] = args[1].data()[31-i];
                XOnlyPubKey pubkey2(pk2);
                if (pubkey2.IsValid() && pubkey2.VerifySchnorr(sighash, args[2])) {
                    fprintf(stderr, "NOTE: your pubkey is probably in reverse order (validation succeeds for flipped pubkey)\n");
                } else if (pubkey2.IsValid() && pubkey2.VerifySchnorr(sh2, args[2])) {
                    fprintf(stderr, "NOTE: your pubkey and sighash are probably both in reverse order (validation succeeds for flipped pubkey and sighash)\n");
                }
            }
        }
    } else {
        CPubKey pubkey(args[1]);
        if (!pubkey.IsValid()) abort("invalid pubkey");
        int64 = pubkey.Verify(sighash, args[2], compact);
    }
    type = T_INT;
}

void Value::do_combine_pubkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two pubkeys)");
    CPubKey pubkey1(args[0]);
    CPubKey pubkey2(args[1]);
    if (!pubkey1.IsValid()) abort("invalid pubkey (first)");
    if (!pubkey2.IsValid()) abort("invalid pubkey (second)");

    const secp256k1_pubkey* d[2];
    secp256k1_pubkey pks[2];
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pks[0], &pubkey1[0], pubkey1.size())) {
        abort("failed to parse pubkey 1");
    }
    d[0] = &pks[0];
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pks[1], &pubkey2[0], pubkey2.size())) {
        abort("failed to parse pubkey 2");
    }
    d[1] = &pks[1];
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_sign, &result, d, 2)) {
        abort("failed to combine pubkeys");
    }
    data.resize(33);
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, data.data(), &publen, &result, SECP256K1_EC_COMPRESSED);
}

void Value::do_tweak_pubkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs a 32 byte value and a public key)");
    auto tweak = args[0];
    CPubKey pubkey1(args[1]);
    if (tweak.size() != 32) abort("invalid tweak value (32 byte value required)");
    if (!pubkey1.IsValid()) abort("invalid pubkey");
    secp256k1_pubkey pk1;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk1, &pubkey1[0], pubkey1.size())) {
        abort("failed to parse pubkey");
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

    if (type != T_DATA) abort("invalid type (must be data)");
    CPubKey pubkey(data);
    if (!pubkey.IsValid()) abort("invalid pubkey");
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk, &pubkey[0], pubkey.size())) {
        abort("failed to parse pubkey");
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

    size_t clen = CPubKey::SIZE;
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

void Value::do_prefix_compact_size() {
    data_value();
    uint8_t sz8 = 0;
    size_t data_len = data.size();
    #define DLW(type) \
        if (sz8) data.insert(data.begin(), &sz8, &sz8 + 1);\
        type t = (type)data_len;\
        data.insert(data.begin(), &t, &t + sizeof(type));\
        return
    if (data_len < 253) { DLW(uint8_t); }
    if (data_len <= std::numeric_limits<unsigned short>::max()) { sz8 = 253; DLW(uint16_t); }
    if (data_len <= std::numeric_limits<unsigned int>::max()) { sz8 = 254; DLW(uint32_t); }
    sz8 = 255; DLW(uint64_t);
}

std::vector<uint8_t> gen_taproot_tagged_hash(const std::string& tag, const std::vector<uint8_t>& msg) {
    CHashWriter tagged_writer = TaggedHash(tag);
    // we do not use the << operator is the std::vector serializer pushes a compact-size prefix
    tagged_writer.write((const char*)msg.data(), msg.size());
    auto r = tagged_writer.GetSHA256();
    return std::vector<uint8_t>(r.begin(), r.end());
}

void Value::do_tagged_hash() {
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() < 2) abort("invalid input (need at least two values: tag, msg[, msg2, ...])");
    std::vector<uint8_t> msg = args[1];
    for (size_t i = 2; i < args.size(); ++i) msg.insert(msg.end(), args[i].begin(), args[i].end());
    if (args.size() > 2) fprintf(stderr, "msg = %s\n", HexStr(msg).c_str());
    data = gen_taproot_tagged_hash(std::string(args[0].begin(), args[0].end()), msg);
}

void Value::do_taproot_tweak_pubkey() {
    if (!secp256k1_context_sign) ECC_Start();

    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two values: pubkey, tweak)");
    if (args[0].size() != 32) abort("invalid input: first argument must be an x-only 32 byte pubkey");
    if (args[1].size() != 32) abort("invalid input: second argument must be a 32 byte tweak");
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_sign, &pubkey, args[0].data())) {
        abort("invalid input: pubkey invalid (parse failed)");
    }
    int is_negated;
    secp256k1_pubkey output_pubkey;

    if (!secp256k1_xonly_pubkey_tweak_add(secp256k1_context_sign, &output_pubkey, &pubkey, args[1].data())) {
        abort("failure: secp256k1_xonly_pubkey_tweak_add call failed");
    }
    data.resize(33);
    size_t output_len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_sign, data.data(), &output_len, &output_pubkey, SECP256K1_EC_COMPRESSED)) {
        abort("failed to serialize pubkey");
    }
    assert(output_len == 33);
    // implementation note: this returns a regular (not x-only) pubkey, from tweaking a x-only pubkey
}

void Value::do_pubkey_to_xpubkey() {
    CPubKey pubkey(data);
    if (!pubkey.IsValid()) abort("invalid pubkey");
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_sign, &pk, &pubkey[0], pubkey.size())) {
        abort("failed to parse pubkey");
    }
    secp256k1_xonly_pubkey xpubkey;
    int pk_parity;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_sign, &xpubkey, &pk_parity, &pk)) {
        abort("failed to convert regular pubkey into x-only pubkey");
    }
    btc_logf("(pk_parity = %d)\n", pk_parity);
    data.resize(32);
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_context_sign, data.data(), &xpubkey)) {
        abort("failed to serialize x-only pubkey");
    }
}

void Value::do_jacobi_symbol() {
    if (type != T_DATA) abort("invalid type (must be data)");

    arith_uint256 n, k, t(0);

    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args)) {
        // user omitting k value; use secp256k1 field
        if (data.size() != 32) abort("n must be 32 bytes (not %zu)", data.size());
        n = UintToArith256(uint256(data));
        k = UintToArith256(SECP256K1_FIELD_SIZE);
    } else if (args.size() != 2) {
        abort("invalid input (needs n and optional k)");
    } else {
        if (args[0].size() != 32) abort("n must be 32 bytes (not %zu)", args[0].size());
        if (args[1].size() != 32) abort("k must be 32 bytes (not %zu)", args[1].size());
        n = UintToArith256(uint256(args[0]));
        k = UintToArith256(uint256(args[1]));
    }

    n = n % k;
    while (n.bits() > 0) {
        while ((n & 1) == 0) {
            n >>= 1;
            uint64_t r = k.GetLow64() & 7;
            t ^= (r == 3 || r == 5);
        }
        arith_uint256 tmp = n;
        n = k;
        k = tmp;
        t ^= ((n & k & 3) == 3);
        n = n % k;
    }
    int64 = k == 1 ? (t.bits() > 0) ? -1 : 1 : 0;
    type = T_INT;
}

#ifdef ENABLE_DANGEROUS

void Value::do_taproot_tweak_seckey() {
    if (!secp256k1_context_sign) ECC_Start();

    // {
    //     auto& ctx = secp256k1_context_sign;

    //     // -in-
    //     auto privkey_vec = ParseHex("3bed2cb3a3acf7b6a8ef408420cc682d5520e26976d354254f528c965612054f");
    //     auto tweak_vec = ParseHex("0b0e6981ce6cac74d055d0e4c25e5b4455a083b3217761327867f26460e0a776");
    //     // -check-
    //     auto pubkey_vec = ParseHex("035bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5");
    //     auto xpubkey_vec = ParseHex("5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5");

    //     secp256k1_keypair keypair;
    //     secp256k1_pubkey pubkey, pubkey2;
    //     secp256k1_xonly_pubkey xpubkey;
    //     std::vector<uint8_t> data, data2;
    //     int pk_parity;
    //     size_t len;

    //     // set up keypair
    //     assert(secp256k1_keypair_create(ctx, &keypair, privkey_vec.data()));
    //     // verify x-only pubkey
    //     assert(secp256k1_keypair_xonly_pub(ctx, &xpubkey, &pk_parity, &keypair));
    //     assert(pk_parity == 1);
    //     data.resize(32);
    //     assert(secp256k1_xonly_pubkey_serialize(ctx, data.data(), &xpubkey));
    //     assert(data == xpubkey_vec);
    //     // verify regular pubkey
    //     assert(secp256k1_keypair_pub(ctx, &pubkey, &keypair));
    //     data.resize(33);
    //     len = 33;
    //     assert(secp256k1_ec_pubkey_serialize(ctx, data.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED));
    //     assert(data == pubkey_vec);
    //     printf("pre-tweak pubkey = %s\n", HexStr(data).c_str());

    //     // apply tweak to pubkey
    //     assert(secp256k1_xonly_pubkey_tweak_add(ctx, &pubkey, &xpubkey, tweak_vec.data()));
    //     // apply the same tweak to the keypair
    //     assert(secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak_vec.data()));
    //     // 'pubkey' (result of xonly_pubkey_tweak_add) and the pubkey from the keypair should be the same
    //     assert(secp256k1_keypair_pub(ctx, &pubkey2, &keypair));
    //     // serialize into data(2)
    //     assert(secp256k1_ec_pubkey_serialize(ctx, data.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED));
    //     data2.resize(33);
    //     assert(len == 33); // should always be 33
    //     assert(secp256k1_ec_pubkey_serialize(ctx, data2.data(), &len, &pubkey2, SECP256K1_EC_COMPRESSED));
    //     assert(len == 33); // should always be 33
    //     printf("post-tweak pubkey:\n%s\n%s\n", HexStr(data).c_str(), HexStr(data2).c_str());
    //     assert(data == data2);

    //     printf("all is swell\n");
    // }

    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two values: privkey, tweak)");
    if (args[0].size() != 32) abort("invalid input: first argument must be a 32 byte private key");
    if (args[1].size() != 32) abort("invalid input: second argument must be a 32 byte tweak");
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(secp256k1_context_sign, &keypair, args[0].data())) {
        abort("failure: unable to create keypair from given private key");
    }

    //     secp256k1_pubkey pubkey;
    //     size_t len = 33;
    // auto& ctx = secp256k1_context_sign;
    // assert(secp256k1_keypair_pub(ctx, &pubkey, &keypair));
    // data.resize(33);
    // len = 33;
    // assert(secp256k1_ec_pubkey_serialize(ctx, data.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED));
    // printf("pre-tweak pubkey = %s\n", HexStr(data).c_str());

    if (!secp256k1_keypair_xonly_tweak_add(secp256k1_context_sign, &keypair, args[1].data())) {
        abort("failure: secp256k1_keypair_xonly_tweak_add call failed");
    }
    // {
    //     assert(secp256k1_keypair_pub(secp256k1_context_sign, &pubkey, &keypair));
    //     std::vector<uint8_t> v;
    //     v.resize(33);
    //     assert(secp256k1_ec_pubkey_serialize(secp256k1_context_sign, v.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED));
    //     printf("resulting pubkey = %s\n", HexStr(v).c_str());
    // }
    data.resize(32);
    // there is no public API to retrieve a private key from a keypair, so this code may break at any
    // point in time without notice
    memcpy(data.data(), keypair.data, 32);
    {
        // verify privkey
        auto r = Value(data);
        r.do_get_pubkey();
        secp256k1_pubkey pk;
        assert(secp256k1_keypair_pub(secp256k1_context_sign, &pk, &keypair));
        std::vector<uint8_t> ser;
        ser.resize(33);
        size_t len = 33;
        assert(secp256k1_ec_pubkey_serialize(secp256k1_context_sign, ser.data(), &len, &pk, SECP256K1_EC_COMPRESSED));
        if (r.data != ser) {
            fprintf(stderr, "fatal: private key derivation failure (resulting pubkeys mismatch: %s vs %s)\n", HexStr(r.data).c_str(), HexStr(ser).c_str());
        }
        assert(r.data == ser);
        fprintf(stderr, "(pubkey verified: %s)\n", HexStr(ser).c_str());
    }
}

void Value::do_combine_privkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two privkeys)");
    for (int i = 0; i < 2; i++) {
        if (args[i].size() != 32) {
            // it is probably a WIF encoded key
            Value wif(args[i]);
            wif.str_value();
            if (wif.str.length() != args[i].size()) abort("invalid input (private key %d must be 32 byte data or a WIF encoded privkey)", i);
            wif.do_decode_wif();
            args[i] = wif.data;
        }
    }

    if (!secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add");
    }

    data = args[0];
}

void Value::do_multiply_privkeys() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs two privkeys)");
    for (int i = 0; i < 2; i++) {
        if (args[i].size() != 32) {
            // it is probably a WIF encoded key
            Value wif(args[i]);
            wif.str_value();
            if (wif.str.length() != args[i].size()) abort("invalid input (private key %d must be 32 byte data or a WIF encoded privkey)", i);
            wif.do_decode_wif();
            args[i] = wif.data;
        }
    }

    if (!secp256k1_ec_privkey_tweak_mul(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add");
    }

    data = args[0];
}

void Value::do_negate_privkey() {
    if (!secp256k1_context_sign) ECC_Start();

    if (type != T_DATA) abort("invalid type (must be data)");

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
    size_t clen = CPubKey::SIZE;
    CPubKey result;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, data.data());
    assert(ret);
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(result.size() == clen);
    assert(result.IsValid());
    data = std::vector<uint8_t>(result.begin(), result.end());
}

void Value::do_get_xpubkey() {
    // the secp256k1_xonly_pubkey_create function was removed, so we do this in two steps; first we convert to a pubkey,
    // and then convert that pubkey into an xpubkey
    do_get_pubkey();
    do_pubkey_to_xpubkey();
}

void Value::sign(bool compact) {
    if (!secp256k1_context_sign) ECC_Start();

    // the value is a script-style push of the sighash followed by the private key
    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs a sighash and a private key)");
    auto& sighash_arg = args[0];
    auto& privkey_arg = args[1];
    if (privkey_arg.size() != 32) {
        // it is probably a WIF encoded key
        Value wif(privkey_arg);
        wif.str_value();
        if (wif.str.length() != privkey_arg.size()) abort("invalid input (private key must be 32 byte data or a WIF encoded privkey)");
        wif.do_decode_wif();
        privkey_arg = wif.data;
    }
    if (privkey_arg.size() != 32) abort("invalid input (private key must be 32 bytes)");
    if (sighash_arg.size() != 32) abort("invalid input (sighash must be 32 bytes)");
    const uint256 sighash(sighash_arg);

    std::vector<uint8_t> sigdata;
    size_t siglen = compact ? 64 : CPubKey::SIGNATURE_SIZE;
    sigdata.resize(siglen);
    uint8_t extra_entropy[32] = {0};
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, sighash.begin(), privkey_arg.data(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    if (compact) {
        secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)sigdata.data(), &sig);
    } else {
        secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)sigdata.data(), &siglen, &sig);
    }
    sigdata.resize(siglen);
    data = sigdata;
}

void Value::sign_schnorr() {
    if (!secp256k1_context_sign) ECC_Start();

    // the value is a script-style push of the sighash followed by the private key
    if (type != T_DATA) abort("invalid type (must be data)");
    std::vector<std::vector<uint8_t>> args;
    if (!extract_values(args) || args.size() != 2) abort("invalid input (needs a sighash and a private key)");
    auto& sighash_arg = args[0];
    auto& privkey_arg = args[1];
    if (privkey_arg.size() != 32) {
        // it is probably a WIF encoded key
        Value wif(privkey_arg);
        wif.str_value();
        if (wif.str.length() != privkey_arg.size()) abort("invalid input (private key must be 32 byte data or a WIF encoded privkey)");
        wif.do_decode_wif();
        privkey_arg = wif.data;
    }
    if (privkey_arg.size() != 32) abort("invalid input (private key must be 32 bytes)");
    if (sighash_arg.size() != 32) abort("invalid input (sighash must be 32 bytes)");
    const uint256 sighash(sighash_arg);

    data.resize(64);
    secp256k1_keypair keypair; // a private key and its public key equivalent
    if (!secp256k1_keypair_create(secp256k1_context_sign, &keypair, privkey_arg.data())) {
        abort("failed to create keypair for given secret key");
    }
    int pk_parity;
    secp256k1_xonly_pubkey xpubkey;
    if (!secp256k1_keypair_xonly_pub(secp256k1_context_sign, &xpubkey, &pk_parity, &keypair)) {
        abort("failed to derive pubkey from keypair (what?)");
    }

    if (!secp256k1_schnorrsig_sign(secp256k1_context_sign, data.data(), sighash.begin(), &keypair, NULL, NULL)) {
        abort("failed to create signature");
    }
    if (!secp256k1_schnorrsig_verify(secp256k1_context_sign, data.data(), sighash.begin(), &xpubkey)) {
        abort("failed to veriy signature");
    }
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
        std::vector<unsigned char> vseed(32); // , secure_allocator<unsigned char>
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
