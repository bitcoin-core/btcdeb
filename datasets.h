// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DATASETS_H
#define BITCOIN_DATASETS_H

#include <map>
#include <string>

inline std::string string_from_file(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("unable to open path " + path);
    char* buf = (char*)malloc(128);
    size_t cap = 128;
    size_t idx = 0;
    long count;
    while (0 < (count = fread(&buf[idx], 1, cap - idx, fp))) {
        idx += count;
        if (idx < cap) break;
        cap <<= 1;
        buf = (char*)realloc(buf, cap);
    }
    buf[idx] = 0;
    std::string r = buf;
    free(buf);
    fclose(fp);
    return r;
}

inline void process_datasets(std::map<char, std::string>& m, bool verbose) {
    std::string dataset = m['X'];
    if (dataset == "1") {
        printf("Available datasets:\n");
        printf("  p2pkh                       A legacy pay-to-pubkey-hash spend from Oct 7, 2020\n");
        if (verbose) printf(
               "    funding txid  = cdc44e86eececa6d726cc93cea4e176fe6191b695444467a3b2bcdfbe64aac02\n"
               "    spending txid = ad7941ba6a7f8f395638233a3dd20a2779c66da516c5b9c9ff4f3d65f2057e3c\n\n"
        );
        printf("  p2sh-p2wpkh                 A non-native Segwit pubkey-hash spend from Aug 24, 2017\n");
        if (verbose) printf(
               "    funding txid  = 42f7d0545ef45bd3b9cfee6b170cf6314a3bd8b3f09b610eeb436d92993ad440\n"
               "    spending txid = c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a\n\n"
        );
        printf("  p2sh-multisig-2-of-2        A 2-of-2 legacy multisig spend from Oct 6, 2020\n");
        if (verbose) printf(
               "    funding txid  = c55c9e0afa43f06e6e9c9277c7fe9768acf3b7b85d61b35770fc38f5f612f76d\n"
               "    spending txid = 245ddb8e1bf5784ceb9d981ffbaae02fb8a73c552dfe23bce50b613b3acbdd62\n\n"
        );
        printf("  p2sh-multisig-invalid-order An invalid multisig, where the signatures are correct, but they've been inserted in the wrong order\n");
        if (verbose) printf(
               "    funding txid  = 7e69687c94c57a878cf711a39870383c6fe93b420f26184a21d020d8ace2df83\n"
               "    spending txid = 56ae0d780759b8126a3eb9be605b1a6e48acb326af527547205d6749afab1a61\n"
        );
        exit(0);
    }
    try {
        if (!m.count('x')) {
            // populate --tx from dataset
            std::string data = string_from_file(std::string("doc/txs/") + dataset + "-tx");
            m['x'] = data;
            if (verbose) printf("loaded spending (output) transaction from dataset %s\n", dataset.c_str());
        }
        if (!m.count('i')) {
            // populate --txin from dataset
            std::string data = string_from_file(std::string("doc/txs/") + dataset + "-in");
            m['i'] = data;
            if (verbose) printf("loaded funding (input) transaction from dataset %s\n", dataset.c_str());
        }
    } catch (const std::runtime_error& err) {
        fprintf(stderr, "error loading from dataset \"%s\": %s\n", dataset.c_str(), err.what());
        exit(1);
    }
}

#endif // BITCOIN_DATASETS_H
