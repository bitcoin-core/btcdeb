#include <cstdio>
#include <unistd.h>

#include <value.h>
#include <merkle.h>
#include <streams.h>

typedef std::vector<unsigned char> valtype;
bool piping = false;

int main(int argc, const char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "syntax: %s <script>\n", argv[0]);
        fprintf(stderr,
            "e.g.: %s \"[\n"
            "   # Source: https://lists.linuxfoundation.org/pipermail/lightning-dev/2015-July/000021.html"
            "   # They present HTLC's R value, or either revocation hash:\n"
            "   # Our revocation value: 8c2574892063f995fdf756bce07f46c1a5193e54cd52837ed91e32008ccf41ac\n"
            "   # Revocation key 1: 9b4b4ae7be32f4728ea406cf9ab8356669c86849c574b51ccf1d871779b13a22\n"
            "   # Revocation key 2: 568b2573a69d9010c82f556f4160d5672d7877f9abebb5d401cbaa3caefdf578\n"
            "   OP_DUP OP_HASH160 aec8d17368a55051e3aa9cf14563a4e537a01a20 OP_EQUAL\n"
            "   OP_SWAP 3b75accc015232a588750a33001827bb012f3c19 OP_EQUAL\n"
            "   OP_ADD OP_SWAP fc2f0717a2e4bb32789f5134a5de83b83e14dc57 OP_EQUAL\n"
            "   OP_ADD\n"
            "   OP_IF\n"
            "       # One hash matched, pay to them.\n"
            "       OP_DUP OP_HASH160 9a0796862bc9dc6128b05ae43dd1807759e66e07 OP_EQUALVERIFY OP_CHECKSIG\n"
            "   OP_ELSE\n"
            "       # Must be us, with HTLC timed out.\n"
            "       # HTLC absolute timeout part\n"
            "       1515988693 OP_CHECKLOCKTIMEVERIFY OP_DROP\n"
            "       # Verification relative timeout\n"
            "       144 OP_CHECKSEQUENCEVERIFY OP_DROP\n"
            "       OP_DUP OP_HASH160 7c3eba56530af354156de76ecd27f5529d2db056 OP_EQUALVERIFY OP_CHECKSIG\n"
            "   OP_ENDIF\n"
            "]\"\n", argv[0]
        );
        fprintf(stderr, "prints root, branches, path, and proof (only root when --position is not used)\n");
        return 1;
    }
    // process -- args until we run out of them; remainder = leaves
    int argi = 1;
    int pos = -1;
    bool preprocessed = false;
    bool legacy = false;
    bool btcdeb = false;
    while (argi < argc && strlen(argv[argi]) > 7 && argv[argi][0] == '-') {
        const char* v = argv[argi];
        if (!strncmp(v, "--position=", strlen("--position="))) {
            pos = atoi(&v[11]);
        } else if (!strcmp(v, "--preprocessed")) {
            preprocessed = true;
        } else if (!strcmp(v, "--legacy")) {
            legacy = true;
        } else if (!strcmp(v, "--btcdeb")) {
            btcdeb = true;
        } else {
            fprintf(stderr, "unknown argument: %s\n", v);
            return -1;
        }
        argi++;
    }
    bool fast = !legacy;
    piping = btcdeb || !isatty(fileno(stdin));
    if (piping) btc_logf = btc_logf_dummy;

    Value script(argv[argi]);
    printf("script: %s\n", script.hex_str().c_str());
    CScript spt = CScript(script.data.begin(), script.data.end());
    auto it = spt.begin();
    opcodetype opcode;
    valtype vchPushValue;
    while (spt.GetOp(it, opcode, vchPushValue)) {
        if (vchPushValue.size() > 0) {
            printf("%s\n", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
        } else {
            printf("%s\n", GetOpName(opcode));
        }
    }

    // 
    // std::vector<Value> leaves = Value::parse_args(argc, argv, argi);
    // std::vector<uint256> hashes;
    // if (preprocessed) {
    //     for (size_t i = 0; i < leaves.size(); i++) {
    //         const std::string& leaf = leaves[i].hex_str();
    //         if (leaf.size() != 64 || !IsHex(leaf)) {
    //             fprintf(stderr, "preprocessed hashes must be hex-encoded 32-bytes: %s\n", leaf.c_str());
    //             return -1;
    //         }
    //         hashes.push_back(uint256(leaves[i].data));
    //     }
    // } else {
    //     for (size_t i = 0; i < leaves.size(); ++i) {
    //         uint256 hash;
    //         const std::vector<unsigned char> leaf = leaves[i].data_value();
    //         CHash256().Write(&leaf[0], leaf.size()).Finalize(hash.begin());
    //         hashes.push_back(hash);
    //     }
    // }
    // if (!piping) {
    //     printf("leaves: [\n");
    //     for (size_t i = 0; i < hashes.size(); ++i) {
    //         printf("\t%s\n", HexStr(hashes[i]).c_str());
    //     }
    //     printf("]\n");
    // }
    // uint256 root;
    // std::vector<uint256> branch;
    // uint32_t path;
    // std::vector<unsigned char> proof;
    // if (pos < 0) {
    //     if (!fast) {
    //         root = ComputeMerkleRoot(hashes, nullptr);
    //     } else {
    //         root = ComputeFastMerkleRoot(hashes);
    //     }
    //     if (!btcdeb) {
    //         btc_logf("root: %s\n", HexStr(root).c_str());
    //     }
    //     if (!piping) {
    //         printf("proposal (1 parameter): TOALTSTACK %s OP_%d OP_MERKLEBRANCHVERIFY 2DROP DROP\n", HexStr(root).c_str(), 2 + preprocessed);
    //     }
    //     if (!piping || btcdeb) {
    //         printf(piping ? "6b20" : "proposal 1 hex:         6b20%s5%db36d75\n", HexStr(root).c_str(), 2 + preprocessed);
    //     }
    //     return 0;
    // }
    // 
    // if (!fast) {
    //     branch = ComputeMerkleBranch(hashes, pos);
    //     root = ComputeMerkleRootFromBranch(hashes[pos], branch, pos);
    //     path = (uint32_t)pos;
    //     // proof is clear
    // } else {
    //     std::pair<std::vector<uint256>, uint32_t> r = ComputeFastMerkleBranch(hashes, pos);
    //     root = ComputeFastMerkleRootFromBranch(hashes[pos], r.first, r.second);
    //     branch.swap(r.first);
    //     path = r.second;
    //     std::vector<MerkleTree> subtrees(hashes.size());
    //     if (hashes.empty()) {
    //         subtrees.emplace_back();
    //     } else {
    //         for (std::size_t i = 0; i < hashes.size(); ++i) {
    //           if (i == static_cast<std::size_t>(pos)) {
    //                 subtrees[i].m_verify.emplace_back(hashes[i]);
    //             } else {
    //                 subtrees[i].m_proof.m_skip.emplace_back(hashes[i]);
    //             }
    //         }
    //         while (subtrees.size() > 1) {
    //             std::vector<MerkleTree> other;
    //             for (auto itr = subtrees.begin(); itr != subtrees.end(); ++itr) {
    //                 auto itr2 = std::next(itr);
    //                 if (itr2 != subtrees.end()) {
    //                     other.emplace_back(*itr++, *itr);
    //                 } else {
    //                     other.emplace_back();
    //                     swap(other.back(), *itr);
    //                 }
    //             }
    //             swap(other, subtrees);
    //         }
    //     }
    //     CVectorWriter ssProof(SER_NETWORK, PROTOCOL_VERSION, proof, proof.size());
    //     ssProof << subtrees[0].m_proof;
    // }
    // 
    // if (!piping) {
    //     printf("root: %s\n", HexStr(root).c_str());
    //     printf("branch: [\n");
    //     for (auto h = branch.begin(); h != branch.end(); ++h) {
    //         printf("\t%s\n", HexStr(*h).c_str());
    //     }
    //     printf("]\n");
    //     printf("path: %d\n", path);
    // } else if (proof.empty()) {
    //     fprintf(stderr, "empty proof\n");
    //     return -1;
    // }
    // if (!proof.empty()) {
    //     if (!piping) {
    //         printf("proof: %s\n", HexStr(proof).c_str());
    //         printf("unlocking proposal (1 parameter):\n");
    //         printf("- script:       TOALTSTACK %s OP_%d OP_MERKLEBRANCHVERIFY 2DROP DROP\n", HexStr(root).c_str(), 2 + preprocessed);
    //     }
    //     if (!piping || btcdeb) {
    //         printf(piping
    //             ? "6b20%s5%db36d75\n"
    //             : "- script (hex): 6b20%s5%db36d75\n",
    //             HexStr(root).c_str(),
    //             2 + preprocessed
    //         );
    //         btc_logf("stack:\n");
    //     }
    //     if (!piping) printf("- item #1:       %s\n", argv[argi + pos]);
    //     printf(piping ? "%s\n" : "- item #1 (hex): %s\n", leaves[pos].hex_str().c_str());
    //     printf(piping ? "%s\n" : "- item #2:       %s\n", HexStr(proof).c_str());
    //     if (!piping) printf("- item #3+:      (argument to script at item #1)\n");
    // }
}
