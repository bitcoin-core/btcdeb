#include <secp256k1.h>

#include "value.h"

#include <support/allocators/secure.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

void ECC_Start();

#define abort(msg...) do { fprintf(stderr, msg); return; } while (0)

bool Value::extract_values(std::vector<std::vector<uint8_t>>& values) {
    values.clear();
    CScript s(data.begin(), data.end());
    CScriptIter pc = s.begin();
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
            if (wif.str.length() != args[i].size()) abort("invalid input (private key %d must be 32 byte data or a WIF encoded privkey)\n", i);
            wif.do_decode_wif();
            args[i] = wif.data;
        }
    }

    if (!secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add\n");
    }

    data = args[0];
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

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
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
