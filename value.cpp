#include <secp256k1.h>

#include "value.h"

#ifdef ENABLE_DANGEROUS
#include <support/allocators/secure.h>
#endif // ENABLE_DANGEROUS

static const unsigned int PRIVATE_KEY_SIZE            = 279;
static const unsigned int COMPRESSED_PRIVATE_KEY_SIZE = 214;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */

/**
 * This parses a format loosely based on a DER encoding of the ECPrivateKey type from
 * section C.4 of SEC 1 <http://www.secg.org/sec1-v2.pdf>, with the following caveats:
 *
 * * The octet-length of the SEQUENCE must be encoded as 1 or 2 octets. It is not
 *   required to be encoded as one octet if it is less than 256, as DER would require.
 * * The octet-length of the SEQUENCE must not be greater than the remaining
 *   length of the key encoding, but need not match it (i.e. the encoding may contain
 *   junk after the encoded SEQUENCE).
 * * The privateKey OCTET STRING is zero-filled on the left to 32 octets.
 * * Anything after the encoding of the privateKey OCTET STRING is ignored, whether
 *   or not it is validly encoded DER.
 *
 * out32 must point to an output buffer of length at least 32 bytes.
 */
static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    memset(out32, 0, 32);
    /* sequence header */
    if (end - privkey < 1 || *privkey != 0x30u) {
        printf("end - privkey < 1?%s || *privkey != 0x30u?%s\n", end - privkey < 1 ? "y" : "n", *privkey != 0x30u ? "y" : "n");
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end - privkey < 1 || !(*privkey & 0x80u)) {
        printf("end - privkey < 1?%s || !(*privkey & 0x80u)?%s\n", end - privkey < 1 ? "y" : "n", !(*privkey & 0x80u) ? "y" : "n");
        return 0;
    }
    size_t lenb = *privkey & ~0x80u; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end - privkey < lenb) {
        return 0;
    }
    /* sequence length */
    size_t len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0u);
    privkey += lenb;
    if (end - privkey < len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end - privkey < 3 || privkey[0] != 0x02u || privkey[1] != 0x01u || privkey[2] != 0x01u) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end - privkey < 2 || privkey[0] != 0x04u) {
        return 0;
    }
    size_t oslen = privkey[1];
    privkey += 2;
    if (oslen > 32 || end - privkey < oslen) {
        return 0;
    }
    memcpy(out32 + (32 - oslen), privkey, oslen);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

/**
 * This serializes to a DER encoding of the ECPrivateKey type from section C.4 of SEC 1
 * <http://www.secg.org/sec1-v2.pdf>. The optional parameters and publicKey fields are
 * included.
 *
 * privkey must point to an output buffer of length at least CKey::PRIVATE_KEY_SIZE bytes.
 * privkeylen must initially be set to the size of the privkey buffer. Upon return it
 * will be set to the number of bytes used in the buffer.
 * key32 must point to a 32-byte raw private key.
 */
static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    assert(*privkeylen >= PRIVATE_KEY_SIZE);
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
        assert(*privkeylen == COMPRESSED_PRIVATE_KEY_SIZE);
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::PUBLIC_KEY_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
        assert(*privkeylen == PRIVATE_KEY_SIZE);
    }
    return 1;
}

static secp256k1_context* secp256k1_context_sign = nullptr;


void ECC_Start();

#define abort(msg...) do { fprintf(stderr, msg); return; } while (0)

bool Value::extract_values(std::vector<std::vector<uint8_t>>& values) {
    values.clear();
    CScript s(data.begin(), data.end());
    auto pc = s.begin();
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
        // std::vector<uint8_t> privkey;
        // size_t privkeylen = PRIVATE_KEY_SIZE;
        // privkey.resize(PRIVATE_KEY_SIZE);
        // if (!ec_privkey_export_der(secp256k1_context_sign, privkey.data(), &privkeylen, args[i].data(), SECP256K1_EC_COMPRESSED)) {
        //     abort("failed exporting privkey %d\n", i);
        // }
        // privkey.resize(privkeylen);
        // args[i] = privkey;
    }

    if (!secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, args[0].data(), args[1].data())) {
        abort("failed call to secp256k1_ec_privkey_tweak_add\n");
    }

    data = args[0];
    // printf("got %s\n", HexStr(args[0]).c_str());
    // convert back
    // data.resize(32);
    // if (!ec_privkey_import_der(secp256k1_context_sign, data.data(), args[0].data(), args[0].size())) {
    //     abort("failed to import resulting privkey\n");
    // }
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

void GetRandBytes(unsigned char* buf, int num)
{
    // TODO: Make this more cross platform
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "unable to open /dev/urandom for GetRandBytes(): sorry! btcdeb does not currently work on your operating system for signature signing\n");
        exit(1);
    }
    fread(buf, 1, num, f);
    fclose(f);
}

#endif // ENABLE_DANGEROUS

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
