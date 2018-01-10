#include <cstdio>

#include <value.h>

typedef std::vector<unsigned char> valtype;

int main(int argc, const char** argv)
{
    if (argc < 2) {
        printf("syntax: %s <program>\n", argv[0]);
        printf("e.g. %s OP_DUP OP_HASH160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 OP_EQUALVERIFY OP_CHECKSIG\n", argv[0]);
        return 1;
    }
    std::vector<Value> result = Value::parse_args(argc, argv, 1);
    for (auto& it : result) {
        fputs(it.hex_str().c_str(), stdout);
    }
    fputc('\n', stdout);
}
