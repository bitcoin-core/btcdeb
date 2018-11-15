#include <uint256.h>
#include <cmath>
#include <hash.h>

struct Element {
    uint256 txid;
    uint32_t n;
    Element(const uint256& txid_in, uint32_t n_in) : txid(txid_in), n(n_in) {}

    inline uint256 GetHash() const {
        return (CHashWriter(SER_GETHASH, 0) << txid << n).GetHash();
    }
};

bool VerifyMerkleProof(const uint256& root, const uint256& element, const std::vector<uint256>& proof) {
    uint256 r = element;
    for (const uint256& h : proof) r = r ^ h;
    return r == root;
}

struct Tree {
    std::vector<uint256> hashes;
    std::vector<Element> elements;
    std::map<uint256, int> ids;

    void UpdateHashes() {
        hashes.clear();
        ids.clear();
        for (const auto& e : elements) {
            auto h = e.GetHash();
            hashes.push_back(h);
            ids[h] = ids.size();
        }
        std::vector<uint256> curr = hashes;
        std::vector<uint256> next;
        while (curr.size() > 1) {
            assert(!(curr.size() & 1));
            size_t count = curr.size() >> 1;
            for (size_t i = 0; i < count; ++i) {
                auto v = curr[i<<1] ^ curr[(i<<1)+1];
                ids[v] = ids.size();
                hashes.push_back(v);
                next.push_back(v);
            }
            curr = next;
            next.clear();
        }
    }

    uint256 GetMerkleRoot() {
        return hashes.size() ? hashes.back() : uint256();
    }

    std::vector<uint256> CalcMerkleProof(size_t eidx) {
        std::vector<uint256> r;
        size_t count = elements.size();
        size_t height = log2(count);
        size_t ridx = eidx;
        for (size_t i = 0; i < height; ++i) {
            size_t sib = eidx ^ 1;
            r.push_back(hashes.at(sib));
            eidx = (eidx >> 1) | (1 << height);
        }
        assert(VerifyMerkleProof(hashes.back(), hashes.at(ridx), r));
        return r;
    }

    void Print() const {
        std::vector<std::string> s;
        std::string spacing = "                                                                                ";
        size_t count = elements.size();
        size_t pos = 0;
        size_t jump = count;
        size_t height = log2(count);
        size_t floor = 1;
        while (jump > 0) {
            std::string spc = spacing.substr(0, (floor * 2) - 1);
            std::string line = "";
            for (size_t dst = pos + jump; pos < dst; ++pos) {
                const auto& x = hashes.at(pos);
                line += char('A' + ids.at(x)) + spc;
            }
            s.push_back(line);
            jump >>= 1;
            floor <<= 1;
        }
        for (int i = s.size() - 1; i >= 0; --i) {
            printf("%s\n", s[i].c_str());
        }
    }
};

struct ForestFull {
    size_t leaves, height;
    std::vector<uint256> hashes;
    ForestFull(size_t _capacity) : leaves(0), height(log2(_capacity)) {
        hashes.resize(_capacity << 1);
    }
};

int main(int argc, char* const* argv)
{
    Tree t;
    for (size_t i = 0; i < 8; ++i) t.elements.emplace_back((CHashWriter(SER_GETHASH, 0) << uint64_t(i + 1024)).GetHash(), i);
    t.UpdateHashes();
    t.Print();
    int idx = arc4random() % 8;
    printf("Merkle proof for %c:", 'A' + idx);
    auto proof = t.CalcMerkleProof(idx);
    for (const auto& x : proof) printf(" %c", 'A' + t.ids.at(x));
    printf("\n");
}
//
// A            14
// B   C        12      13
// D E F G      8   9   10  11
// HIJKLMNO     0 1 2 3 4 5 6 7
// 01234567

// Prove 0=H : I, E, C      1, 9 (1), 13 (1)
// A
// B       _C_
// D   _E_ F G
// H_I_JKLMNO
// 01  234567

// Prove 1=I : H, E, C      0, 9 (1), 13 (1)
// A
// B       _C_
// D   _E_ F G
// _H_IJKLMNO
// 0  1234567

// Prove 2=J : K, D, C      3, 8 (0), 13 (1)
// A
// B       _C_
// _D_ E   F G
// HI  J_K_LMNO
// 01  23  4567

// Prove 3=K : J, D, C      2, 8 (0), 13 (1)
// A
// B       _C_
// _D_ E   F G
// HI  _J_KLMNO
// 01  2  34567
//

// Prove 7=O : N, F, B      6, 10 (0), 12 (0)
// A
// B   C
// D E F G
// HIJKLMNO
// 01234567
//