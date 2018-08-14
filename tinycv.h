// Copyright (c) 2018 Karl-Johan Alm <kalle.alm@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TINYCV_H
#define BITCOIN_TINYCV_H

#include <uint256.h>
#include <tinytx.h>
#include <tinyblock.h>

namespace tiny {

extern int coin_view_version;

template<typename Stream>
static inline void SerializeBoolVector(Stream& s, const std::vector<bool>& v) {
    uint64_t len = v.size();
    s << COMPACTSIZE(len);
    for (size_t i = 0; i < v.size(); i += 8) {
        uint8_t b = v[i];
        if (i + 7 < v.size()) {
            b 
            |= (v[i+1] << 1)
            |  (v[i+2] << 2)
            |  (v[i+3] << 3)
            |  (v[i+4] << 4)
            |  (v[i+5] << 5)
            |  (v[i+6] << 6)
            |  (v[i+7] << 7);
        } else {
            for (size_t j = i + 1; j < v.size(); ++j) {
                b |= (v[j] << (j-i));
            }
        }
        s << b;
    }
}

template<typename Stream>
static inline uint64_t DeserializeBoolVector(Stream& s, std::vector<bool>& v) {
    uint64_t trues = 0;
    size_t i = 0;
    uint64_t len = ::ReadCompactSize(s);
    v.resize(len);
    while (i < v.size()) {
        uint8_t b;
        s >> b;
        if (i + 7 < v.size()) {
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b & 1); b >>= 1;
            trues += (v[i++] = b);
        } else {
            for (; i < v.size(); ++i) {
                trues += (v[i] = b & 1);
                b >>= 1;
            }
        }
    }
    return trues;
}

struct coin {
    std::shared_ptr<tx> x;
    std::vector<bool> spent;
    uint32_t spendable = 0;
    coin() {}
    coin(std::shared_ptr<tx> x_in) {
        x = x_in;
        spent.resize(x->vout.size());
        // bool necessary = false;
        for (size_t i = 0; i < x->vout.size(); ++i) {
            spent[i] = x->vout[i].provably_unspendable();
            spendable += !spent[i];
            // necessary |= CScript(x->vout[i].scriptPubKey.begin(), x->vout[i].scriptPubKey.end()).IsPayToScriptHash();
        }
        // if (!necessary) spendable = 0;
    }
    bool spend_exhausts(int n) {
        assert(!spent[n]);
        spent[n] = true;
        return !--spendable;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead()) {
            x = std::make_shared<tx>();
            READWRITE(*x.get());
            spendable = DeserializeBoolVector(s, spent);
        } else {
            READWRITE(*x.get());
            SerializeBoolVector(s, spent);
        }
        if (coin_view_version == 1) {
            uint8_t u;
            READWRITE(u);
        }
    }
};

class view {
protected:
    std::map<uint256,coin> coin_map;
    bool dupe_coinbase_tx(const uint256& hash) {
        static std::set<uint256> set{
            uint256S("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"), // 91842
            uint256S("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"), // 91880
        };
        return set.count(hash);
    }

public:
    bool operator==(const view& other) const {
        bool equal = true;
        for (const auto& x : coin_map) {
            if (other.coin_map.count(x.first) != 1) {
                printf("other is missing txid %s\n", x.first.ToString().c_str());
                equal = false;
            }
        }
        for (const auto& x : other.coin_map) {
            if (coin_map.count(x.first) != 1) {
                printf("I am missing txid %s\n", x.first.ToString().c_str());
                equal = false;
            }
        }
        return equal;
    }
    void insert(std::shared_ptr<tx> x) {
        if (!x->IsCoinBase()) {
            // spend inputs
            for (const auto& in : x->vin) {
                auto& c = coin_map.at(in.prevout.hash);
                if (c.spend_exhausts(in.prevout.n)) {
                    // tx can be thrown out as all its outputs were spent
                    coin_map.erase(in.prevout.hash);
                }
            }
        }
        // add new outputs
        coin c(x);
        if (!c.spendable) {
            // no spendable outputs so.. bye
            return;
        }
        assert(dupe_coinbase_tx(x->hash) || coin_map.count(x->hash) == 0);
        coin_map[x->hash] = c;
    }
    tx* get(const uint256& txid) const {
        if (coin_map.count(txid) == 0) {
            printf("MISSING TXID %s\n", txid.ToString().c_str());
        }
        assert(coin_map.count(txid) == 1);
        return coin_map.at(txid).x.get();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(coin_view_version);
        READWRITE(coin_map);
        coin_view_version = 2;
    }
};

} // namespace tiny

#endif // BITCOIN_TINYCV_H
