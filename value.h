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

struct Value {
    enum {
        T_STRING,
        T_INT,
        T_DATA,
    } type;
    int64_t i;
    std::vector<uint8_t> data;
    std::string str;
    Value(const char* v, size_t vlen = 0) {
        if (!vlen) vlen = strlen(v);
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
                // can it be an opcode too?
                if (i >= 0 && i < 16) {
                    btc_logf("warning: ambiguous input %s is interpreted as a numeric value (%s), not as an opcode (OP_%s). Use OP_%s to force into op code interpretation\n", v, v, v, v);
                }
                type = T_INT;
                return;
            }
        }
        // hex string?
        if (!(vlen & 1)) {
            data = ParseHex(v);
            if (data.size() == (vlen >> 1)) {
                type = T_DATA;
                return;
            }
        }
        // string
        str = v;
        type = T_STRING;
    }
    std::vector<uint8_t> data_value() {
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
        case T_DATA:
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
            printf("got "); println();
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
