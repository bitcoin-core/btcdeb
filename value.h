#ifndef included_value_h_
#define included_value_h_

#include <vector>
#include <string>
#include <utilstrencodings.h>
#include <script.h>
#include <tinyformat.h>
#include <crypto/sha256.h>
#include <crypto/ripemd160.h>
// #include <hash.h>
#include <base58.h>
#include <bech32.h>

template<typename T1, typename T2>
inline void insert(T1& a, T2&& b) {
    a.insert(a.end(), b.begin(), b.end());
}

struct Value {
    enum {
        T_STRING,
        T_INT,
        T_DATA,
    } type;
    int64_t i;
    std::vector<uint8_t> data;
    std::string str;
    static std::vector<Value> parse_args(const std::vector<const char*> args, bool embedding = false) {
        std::vector<Value> result;
        for (auto& v : args) {
            size_t vlen = strlen(v);
            if (vlen > 0) {
                // brackets embed
                if (v[0] == '[' && v[vlen-1] == ']') {
                    result.emplace_back(parse_args(&v[1], vlen - 2, true));
                } else {
                    result.emplace_back(v, vlen, embedding);
                }
            }
        }
        return result;
    }
    static std::vector<Value> parse_args(const size_t argc, const char** argv, size_t argidx = 0) {
        std::vector<const char*> args;
        for (size_t i = argidx; i < argc; i++) args.push_back(argv[i]);
        return parse_args(args);
    }
    static std::vector<Value> parse_args(const char* args_string, const size_t args_len, bool embedding = false) {
        std::vector<const char*> args;
        char* args_ptr[args_len];
        size_t arg_idx = 0;
        size_t start = 0;
        for (size_t i = 0; i <= args_len; i++) {
            char ch = args_string[i - (i == args_len)];
            if (i == args_len || (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '#')) {
                if (start == i) {
                    start++;
                } else {
                    args_ptr[arg_idx] = strndup(&args_string[start], i - start);
                    args.push_back(args_ptr[arg_idx]);
                    arg_idx++;
                    start = i + 1;
                }
                if (ch == '#') {
                    // trim out remainder of this line
                    while (i < args_len && args_string[i] != '\n' && args_string[i] != '\r') {
                        i++;
                    }
                    start = i + 1;
                }
            }
        }
        std::vector<Value> result = parse_args(args, embedding);
        for (size_t i = 0; i < arg_idx; i++) free(args_ptr[i]);
        return result;
    }
    Value(std::vector<Value> v, bool fallthrough_single = false) {
        if (fallthrough_single && v.size() == 1) {
            type = v[0].type;
            data = v[0].data;
            str = v[0].str;
            i = v[0].i;
            return;
        }
        type = T_DATA;
        for (auto& it : v) {
            insert(data, it.data_value(true));
        }
    }
    Value(const char* v, size_t vlen = 0, bool pushed = false, bool stack = false) {
        if (!vlen) vlen = strlen(v);
        if (vlen == 2 && v[0] == '0' && v[1] == 'x') {
            type = T_DATA;
            data.clear();
            return;
        }
        str = v;
        type = T_STRING;
        if (vlen > 1 && v[0] == '[' && v[vlen - 1] == ']') {
            for (auto& it : parse_args(&v[1], vlen - 2, true)) {
                insert(data, it.data_value(true));
            }
            type = T_DATA;
            return;
        }
        i = atoll(v);
        if (i != 0) {
            // verify
            char buf[vlen + 1];
            sprintf(buf, "%lld", i);
            if (!strcmp(buf, v)) {
                // verified; can it be a hexstring too?
                if (!(vlen & 1)) {
                    std::vector<unsigned char> pushData(ParseHex(v));
                    if (pushData.size() == (vlen >> 1)) {
                        // it can; warn about using 0x for hex
                        btc_logf("warning: ambiguous input %s is interpreted as a numeric value; use 0x%s to force into hexadecimal interpretation\n", v, v);
                    }
                }
                if (i >= 1 && i <= 16) {
                    btc_logf("warning: ambiguous input %s is interpreted as a numeric value; use OP_%s to force into opcode\n", v, v);
                }
                type = T_INT;
                return;
            }
        }
        // opcode check
        opcodetype opc = GetOpCode(v);
        if (opc != OP_INVALIDOPCODE) {
            type = T_DATA;
            CScript script = CScript() << opc;
            insert(data, script);
            return;
        }
        // hex string?
        if (!(vlen & 1)) {
            if (vlen > 2 && v[0] == '0' && v[1] == 'x') {
                vlen -= 2;
                v = &v[2];
            }
            data = ParseHex(v);
            if (data.size() == (vlen >> 1)) {
                type = T_DATA;
                if (data.size() < 2 && !stack) {
                    // pull out int64 and push that
                    int64_t i64 = int_value();
                    CScript s = CScript() << i64;
                    data.clear();
                    insert(data, s);
                    return;
                }
                if (pushed) {
                    CScript s = CScript() << data;
                    data.clear();
                    insert(data, s);
                }
                return;
            }
        }
    }
    Value& operator+=(const Value& other) {
        data_value();
        insert(data, other.data_value());
        return *this;
    }
    std::vector<uint8_t> data_value(bool script = false) const {
        return const_cast<Value*>(this)->data_value(script);
    }
    std::vector<uint8_t> data_value(bool script = false) {
        if (type == T_DATA) return data;
        if (script && type == T_INT) {
            data.clear();
            insert(data, CScript() << i);
            return data;
        }
        switch (type) {
        case T_INT:
            if (i < 256) {
                data.resize(1);
                data[0] = (uint8_t)(i & 0xff);
                return data;
            }
            if (i < 0x100000000) {
                data.resize(4);
                memcpy(data.data(), &i, 4);
                return data;
            }
            data.resize(8);
            memcpy(data.data(), &i, 8);
            return data;
        default:
            // ascii representation
            data.resize(str.length());
            memcpy(data.data(), str.data(), str.length());
            return data;
        }
    }
    std::string hex_str() {
        switch (type) {
        case T_INT:
            if (i < 256) return strprintf("%02x", i);
            if (i < 0x100000000) return strprintf("%08x", i);
            return strprintf("%16x", i);
        case T_DATA:
            return HexStr(data);
        default:
            fprintf(stderr, "cannot convert string into hex value: %s\n", str.c_str());
            return "";
        }
    }
    int64_t int_value() {
        switch (type) {
        case T_INT:
            return i;
        case T_DATA:
            if (data.size() > 8) {
                fprintf(stderr, "%zu bytes of data cannot fit in an integer (max 8 bytes)\n", data.size());
                return -1;
            }
            memcpy(&i, data.data(), data.size());
            return i;
        default:
            fprintf(stderr, "cannot convert string into integer value: %s\n", str.c_str());
            return -1;
        }
    }
    void do_reverse() {
        std::vector<char> vc;
        int64_t j;
        switch (type) {
        case T_INT:
            for (int64_t z = i; z; z = z / 10) {
                vc.push_back(z % 10);
            }
            j = 0;
            for (auto it = vc.rbegin(); it != vc.rend(); ++it) {
                j = (j * 10) + *it;
            }
            i = j;
            return;
        case T_DATA:
            std::reverse(std::begin(data), std::end(data));
            return;
        case T_STRING:
            std::reverse(str.begin(), str.end());
            return;
        }
    }
    void do_sha256() {
        data_value();
        type = T_DATA;
        CSHA256 s;
        s.Write(data.data(), data.size());
        data.resize(CSHA256::OUTPUT_SIZE);
        s.Finalize(data.data());
    }
    void do_ripemd160() {
        data_value();
        type = T_DATA;
        CRIPEMD160 s;
        s.Write(data.data(), data.size());
        data.resize(CRIPEMD160::OUTPUT_SIZE);
        s.Finalize(data.data());
    }
    void do_hash256() {
        do_sha256();
        do_sha256();
    }
    void do_hash160() {
        do_sha256();
        do_ripemd160();
    }
    void do_base58enc() {
        data_value();
        str = EncodeBase58(data);
        type = T_STRING;
    }
    void do_base58dec() {
        if (type != T_STRING) {
            fprintf(stderr, "cannot base58-decode non-string value\n");
            return;
        }
        if (!DecodeBase58(str, data)) {
            fprintf(stderr, "decode failed\n");
        }
        type = T_DATA;
    }
    void do_base58chkenc() {
        data_value();
        str = EncodeBase58Check(data);
        type = T_STRING;
    }
    void do_base58chkdec() {
        if (type != T_STRING) {
            fprintf(stderr, "cannot base58-decode non-string value\n");
            return;
        }
        if (!DecodeBase58Check(str, data)) {
            fprintf(stderr, "decode failed\n");
        }
        type = T_DATA;
    }
    void do_bech32enc() {
        data_value();
        std::vector<unsigned char> tmp = {0};
        ConvertBits<8, 5, true>(tmp, data.begin(), data.end());
        str = bech32::Encode("bc", tmp);
        type = T_STRING;
    }
    void do_bech32dec() {
        if (type != T_STRING) {
            fprintf(stderr, "cannot bech32-decode non-string value\n");
            return;
        }
        auto bech = bech32::Decode(str);
        if (bech.first == "") {
            fprintf(stderr, "failed to bech32-decode string\n");
            return;
        }
        // Bech32 decoding
        int version = bech.second[0]; // The first 5 bit symbol is the witness version (0-16)
        // data = r.second;
        printf("(bech32 HRP = %s)\n", bech.first.c_str());
        type = T_DATA;
        data.clear();
        // The rest of the symbols are converted witness program bytes.
        if (ConvertBits<5, 8, false>(data, bech.second.begin() + 1, bech.second.end())) {
            if (version == 0) {
                {
                    if (data.size() == 20) {
                        // std::copy(data.begin(), data.end(), keyid.begin());
                        // return keyid;
                        return;
                    }
                }
                {
                    // WitnessV0ScriptHash scriptid;
                    if (data.size() == 32) {
                        // std::copy(data.begin(), data.end(), scriptid.begin());
                        // return scriptid;
                        return;
                    }
                }
                fprintf(stderr, "warning: unknown size %zu\n", data.size());
                // return CNoDestination();
                return;
            }
            if (version > 16 || data.size() < 2 || data.size() > 40) {
                return;
                // return CNoDestination();
            }
            // WitnessUnknown unk;
            // unk.version = version;
            // std::copy(data.begin(), data.end(), unk.program);
            // unk.length = data.size();
            // return unk;
            return;
        }
    }
#ifdef ENABLE_DANGEROUS
    void do_encode_wif() {
        data_value();
        data.insert(data.begin(), 0x80);    // main net
        // data.insert(data.end(),   0x01);    // compressed
        Value hashed(*this);
        hashed.do_hash256();
        data.insert(data.end(), hashed.data.begin(), hashed.data.begin() + 4);
        do_base58enc();
    }
    void do_decode_wif() {
        if (type != T_STRING) {
            fprintf(stderr, "input must be a WIF string; type = %d\n", type);
            return;
        }
        do_base58dec();
        if (data.size() < 4) {
            fprintf(stderr, "base58 decoding failed\n");
            return;
        }
        std::vector<uint8_t> chksum(data.end() - 4, data.end());
        data.resize(data.size() - 4);
        if (data[0] != 0x80) {
            fprintf(stderr, "unexpected prefix 0x%02x (expected 0x80)\n", data[0]);
        }
        // check sum validation part before removing prefixes/suffixes
        Value hashed(*this);
        hashed.do_hash256();
        hashed.data.resize(4);
        for (int i = 0; i < 4; i++) {
            if (hashed.data[i] != chksum[i]) {
                fprintf(stderr, "checksum failure for byte %d: 0x%02x != 0x%02x\n", i, chksum[i], hashed.data[i]);
                return;
            }
        }
        data = std::vector<uint8_t>(data.begin() + 1, data.end());
    }
#endif // ENABLE_DANGEROUS
    void println() {
        switch (type) {
        case T_INT:
            printf("%lld\n", i);
            return;
        case T_DATA:
            for (auto it : data) printf("%02x", it);
            printf("\n");
            return;
        case T_STRING:
            printf("%s\n", str.c_str());
        }
    }
};

#endif // included_value_h_
