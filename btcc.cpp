#include <cstdio>

#include <script.h>
#include <utilstrencodings.h>

typedef std::vector<unsigned char> valtype;

int main(int argc, const char** argv)
{
    if (argc < 2) {
        printf("syntax: %s <program>\n", argv[0]);
        printf("e.g. %s OP_DUP OP_HASH160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 OP_EQUALVERIFY OP_CHECKSIG\n", argv[0]);
        return 1;
    }
    // opcodetype op_n[] = {OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
    //     OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, }
    CScript script;
    for (int i = 1; i < argc; i++) {
        const char* v = argv[i];
        size_t vlen = strlen(v);
        // empty strings are ignored
        if (!v[0]) continue;
        // number?
        int64_t n = atoll(v);
        if (n != 0) {
            // verify
            char buf[vlen + 1];
            sprintf(buf, "%lld", n);
            if (!strcmp(buf, v)) {
                // verified; can it be a hexstring too?
                if (!(vlen & 1)) {
                    std::vector<unsigned char> pushData(ParseHex(v));
                    if (pushData.size() == (vlen >> 1)) {
                        // it can; warn about using 0x for hex
                        fprintf(stderr, "warning: ambiguous input %s is interpreted as a numeric value; use 0x%s to force into hexadecimal interpretation\n", v, v);
                    }
                }
                // // can it be an opcode too?
                // if (n < 16) {
                //     fprintf(stderr, "warning: ambiguous input %s is interpreted as a numeric value (%s), not as an opcode (OP_%s). Use OP_%s to force into op code interpretation\n", v, v, v, v);
                // }
                script << n;
                continue;
            }
        }
        // hex string?
        if (!(vlen & 1)) {
            if (vlen > 1 && v[0] == '0' && v[1] == 'x') {
                v = &v[2];
                vlen -= 2;
            }
            std::vector<unsigned char> pushData(ParseHex(v));
            if (pushData.size() == (vlen >> 1)) {
                script << pushData;
                continue;
            }
        }
        opcodetype opc = GetOpCode(v);
        if (opc != OP_INVALIDOPCODE) {
            script << opc;
            continue;
        }
        fprintf(stderr, "error: invalid opcode %s\n", v);
    }
    for (auto it = script.begin(); it != script.end(); it++) printf("%02x", (*it));
    printf("\n");
}
