#include <cstdio>
#include <unistd.h>

#include <value.h>
#include <merkle.h>
#include <streams.h>

typedef std::vector<unsigned char> valtype;
bool piping = false;

void btc_logf_dummy(const char* fmt...) {}

int main(int argc, const char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "syntax: %s [--position=<index>] [--preprocessed] [--legacy] [--btcdeb] <leaf> [<leaf 2> [<leaf 3> [...]]]\n", argv[0]);
        fprintf(stderr,
            " --position=<index> (integer, optional) The index of the element to construct a proof for. If not specified, only the Merkle root is calculated.\n"
            " --preprocessed     (boolean, optional, default=false) Whether the leaves list contains data to be hashed (false), or already-processed hashes (true). If true, the leaves must consist entirely of 64-byte hex-encoded hashes.\n"
            " --legacy           (boolean, optional, default=false) Whether fast Merkle trees, or the original CVE-2012-2459 vulnerable, Satoshi-authored Merkle trees are to be used (--legacy will use the old variant).\n"
            " --btcdeb           (boolean, optional) Format output for piping into btcdeb (only useful with --position set).\n"
        );
        fprintf(stderr, "e.g.: %s 1 '[FROMALTSTACK 1 EQUALVERIFY]' '[FROMALTSTACK 2 EQUALVERIFY]'\n", argv[0]);
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

    std::vector<Value> leaves = Value::parse_args(argc, argv, argi);
    std::vector<uint256> hashes;
    if (preprocessed) {
        for (size_t i = 0; i < leaves.size(); i++) {
            const std::string& leaf = leaves[i].hex_str();
            if (leaf.size() != 64 || !IsHex(leaf)) {
                fprintf(stderr, "preprocessed hashes must be hex-encoded 32-bytes: %s\n", leaf.c_str());
                return -1;
            }
            hashes.push_back(uint256S(leaf));
        }
    } else {
        for (size_t i = 0; i < leaves.size(); ++i) {
            uint256 hash;
            const std::vector<unsigned char> leaf = leaves[i].data_value();
            CHash256().Write(&leaf[0], leaf.size()).Finalize(hash.begin());
            hashes.push_back(hash);
        }
    }
    uint256 root;
    std::vector<uint256> branch;
    uint32_t path;
    std::vector<unsigned char> proof;
    if (pos < 0) {
        if (!fast) {
            root = ComputeMerkleRoot(hashes, nullptr);
        } else {
            root = ComputeFastMerkleRoot(hashes);
        }
        btc_logf("root: ");
        if (!btcdeb) {
            for (int it = 0; it < 32; it++) {
                printf("%02x", root.begin()[it]);
            }
            printf("\n");
        }
        if (!piping) {
            printf("proposal (1 parameter): TOALTSTACK ");
            for (int it = 0; it < 32; it++) {
                printf("%02x", root.begin()[it]);
            }
            printf(" OP_2 OP_MERKLEBRANCHVERIFY 2DROP DROP\n");
        }
        if (!piping || btcdeb) {
            printf(piping ? "6b20" : "proposal 1 hex:         6b20");
            for (int it = 0; it < 32; it++) {
                printf("%02x", root.begin()[it]);
            }
            printf("52b36d75\n");
        }
        return 0;
    }

    if (!fast) {
        branch = ComputeMerkleBranch(hashes, pos);
        root = ComputeMerkleRootFromBranch(hashes[pos], branch, pos);
        path = (uint32_t)pos;
        // proof is clear
    } else {
        std::pair<std::vector<uint256>, uint32_t> r = ComputeFastMerkleBranch(hashes, pos);
        root = ComputeFastMerkleRootFromBranch(hashes[pos], r.first, r.second);
        branch.swap(r.first);
        path = r.second;
        std::vector<MerkleTree> subtrees(hashes.size());
        if (hashes.empty()) {
            subtrees.emplace_back();
        } else {
            for (std::size_t i = 0; i < hashes.size(); ++i) {
              if (i == static_cast<std::size_t>(pos)) {
                    subtrees[i].m_verify.emplace_back(hashes[i]);
                } else {
                    subtrees[i].m_proof.m_skip.emplace_back(hashes[i]);
                }
            }
            while (subtrees.size() > 1) {
                std::vector<MerkleTree> other;
                for (auto itr = subtrees.begin(); itr != subtrees.end(); ++itr) {
                    auto itr2 = std::next(itr);
                    if (itr2 != subtrees.end()) {
                        other.emplace_back(*itr++, *itr);
                    } else {
                        other.emplace_back();
                        swap(other.back(), *itr);
                    }
                }
                swap(other, subtrees);
            }
        }
        CVectorWriter ssProof(SER_NETWORK, PROTOCOL_VERSION, proof, proof.size());
        ssProof << subtrees[0].m_proof;
    }

    // printf("root: %s\n", root.ToString().c_str());
    if (!piping) {
        printf("root: ");
        for (int it = 0; it < 32; it++) {
            printf("%02x", root.begin()[it]);
        }
        printf("\n");
        printf("branch: [\n");
        for (auto h = branch.begin(); h != branch.end(); ++h) {
            printf("\t%s\n", h->GetHex().c_str());
        }
        printf("]\n");
        printf("path: %d\n", path);
    } else if (proof.empty()) {
        fprintf(stderr, "empty proof\n");
        return -1;
    }
    if (!proof.empty()) {
        if (!piping) {
            printf("proof: %s\n", HexStr(proof).c_str());
            printf("unlocking proposal (1 parameter):\n");
            printf("- script:       TOALTSTACK ");
            for (int it = 0; it < 32; it++) {
                printf("%02x", root.begin()[it]);
            }
            printf(" OP_2 OP_MERKLEBRANCHVERIFY 2DROP DROP\n");
        }
        if (!piping || btcdeb) {
            printf(piping ? "6b20" : "- script (hex): 6b20");
            for (int it = 0; it < 32; it++) {
                printf("%02x", root.begin()[it]);
            }
            printf("52b36d75\n");
            btc_logf("stack:\n");
        }
        if (!piping) printf("- item #1:       %s\n", argv[argi + pos]);
        printf(piping ? "%s\n" : "- item #1 (hex): %s\n", leaves[pos].hex_str().c_str());
        printf(piping ? "%s\n" : "- item #2:       %s\n", HexStr(proof).c_str());
        if (!piping) printf("- item #3+:      (argument to script at item #1)\n");
    }
}
