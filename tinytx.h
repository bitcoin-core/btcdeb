// Copyright (c) 2018 Karl-Johan Alm <kalle.alm@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TINYTX_H
#define BITCOIN_TINYTX_H

#include <uint256.h>

#ifdef TINY_MINIMAL
#   define TINY_NOSERIALIZE
#   define TINY_NOUTILSTRENC
#   define TINY_NOHASH
#endif

#ifndef TINY_NOSERIALIZE
#   include <serialize.h>
#endif

#ifndef TINY_NOUTILSTRENC
#   include <utilstrencodings.h>
#endif

#ifndef TINY_NOHASH
#   include <hash.h>
#   ifdef TINY_NOSERIALIZE
#       error tiny hashes require serialization (disable TINY_NOSERIALIZE)
#   endif
#endif

#ifndef TINY_NOSCRIPT
#   include <script/script.h>
#endif

namespace tiny {

typedef int64_t amount;
static const amount COIN = 100000000;

inline std::string coin_str(amount sat) {
    char buf[128];
    char* pbuf = buf + sprintf(buf, "%lld.%08lld", sat / COIN, sat % COIN);
    return std::string(buf, pbuf);
}

static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

struct outpoint {
    uint256 hash;
    uint32_t n;
    outpoint() : n((uint32_t)-1) {}
    outpoint(const uint256& hash_in, uint32_t n_in) : hash(hash_in), n(n_in) {}

#ifndef TINY_NOSERIALIZE
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }
#endif

    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    bool operator==(const outpoint& other) const { return hash == other.hash && n == other.n; }
    bool operator<(const outpoint& other) const { return hash < other.hash || (hash == other.hash && n < other.n); }

    std::string ToString() const { return "outpoint(" + hash.ToString().substr(0,10) + ", " + std::to_string(n) + ")"; }
};

typedef std::vector<uint8_t> script_data_t;
typedef std::vector<std::vector<uint8_t>> script_stack_t;

struct txin {
    outpoint prevout;
    script_data_t scriptSig;
    uint32_t sequence;
    script_stack_t scriptWit;

    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    txin() : sequence(SEQUENCE_FINAL) {}

    txin(outpoint prevout_in, script_data_t scriptSig_in=script_data_t(), uint32_t sequence_in=SEQUENCE_FINAL) {
        prevout = prevout_in;
        scriptSig = scriptSig_in;
        sequence = sequence_in;
    }

#ifndef TINY_NOSERIALIZE
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(sequence);
    }
#endif

#ifndef TINY_NOUTILSTRENC
    std::string scriptWitString() const {
        std::string ret = "scriptWit(";
        for (unsigned int i = 0; i < scriptWit.size(); i++) {
            if (i) {
                ret += ", ";
            }
            ret += HexStr(scriptWit[i]);
        }
        return ret + ")";
    }
#endif

    std::string ToString() const {
        std::string str;
        str += "txin(";
        str += prevout.ToString();
#ifndef TINY_NOUTILSTRENC
        if (prevout.IsNull()) {
            str += ", coinbase " + HexStr(scriptSig);
        } else {
            str += ", scriptSig=" + HexStr(scriptSig).substr(0, 24);
        }
#endif
        if (sequence != SEQUENCE_FINAL) {
            str += ", sequence=" + std::to_string(sequence);
        }
        str += ")";
        return str;
    }
};

struct txout {
    amount value;
    script_data_t scriptPubKey;

    txout() : value(-1) {}
    txout(const amount& value_in, script_data_t scriptPubKey_in) : value(value_in), scriptPubKey(scriptPubKey_in) {}

#ifndef TINY_NOSCRIPT
    /**
     * Determine if this output is provably unspendable. Even if this method
     * returns false, the output may still be unspendable, but if it returns
     * true, the output is guaranteed to never be spendable.
     */
    bool provably_unspendable() const {
        CScript s = CScript(scriptPubKey.begin(), scriptPubKey.end());
        CScriptIter it = s.begin();
        opcodetype opcode;
        std::vector<unsigned char> vchPushValue;
        while (s.GetOp(it, opcode, vchPushValue)) {
            if (opcode == OP_RETURN) return true;
        }
        return false;
    }
#endif

#ifndef TINY_NOSERIALIZE
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(value);
        READWRITE(scriptPubKey);
    }
#endif

    std::string ToString() const { 
#ifndef TINY_NOUTILSTRENC
        return "txout(value=" + coin_str(value) + ", scriptPubKey=" + HexStr(scriptPubKey).substr(0, 30) + ")";
#else
        return "txout(value=" + coin_str(value) + ")";
#endif
    }
};

/**
* Basic transaction serialization format:
* - int32_t nVersion
* - std::vector<CTxIn> vin
* - std::vector<CTxOut> vout
* - uint32_t nLockTime
*
* Extended transaction serialization format:
* - int32_t nVersion
* - unsigned char dummy = 0x00
* - unsigned char flags (!= 0)
* - std::vector<CTxIn> vin
* - std::vector<CTxOut> vout
* - if (flags & 1):
*   - CTxWitness wit;
* - uint32_t nLockTime
*/

struct tx {
    std::vector<txin> vin;
    std::vector<txout> vout;
    int32_t version;
    uint32_t locktime;

    uint256 hash;

    tx() : vin(), vout(), version(2), locktime(0), hash() {}

    friend bool operator==(const tx& a, const tx& b)
    {
        return a.hash == b.hash;
    }

#ifndef TINY_NOHASH
    void UpdateHash() {
        hash = SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    }
#endif

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (vin[i].scriptWit.size()) {
                return true;
            }
        }
        return false;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

#ifndef TINY_NOSERIALIZE
    template<typename Stream>
    inline void Unserialize(Stream& s) {
        const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

        s >> version;
        unsigned char flags = 0;
        vin.clear();
        vout.clear();
        /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
        s >> vin;
        if (vin.size() == 0 && fAllowWitness) {
            /* We read a dummy or an empty vin. */
            s >> flags;
            if (flags != 0) {
                s >> vin;
                s >> vout;
            }
        } else {
            /* We read a non-empty vin. Assume a normal vout follows. */
            s >> vout;
        }
        if ((flags & 1) && fAllowWitness) {
            /* The witness flag is present, and we support witnesses. */
            flags ^= 1;
            for (size_t i = 0; i < vin.size(); i++) {
                s >> vin[i].scriptWit;
            }
        }
        if (flags) {
            /* Unknown flag in the serialization */
            throw std::ios_base::failure("Unknown transaction optional data");
        }
        s >> locktime;
#ifndef TINY_NOHASH
        UpdateHash();
#endif
    }

    template<typename Stream>
    inline void Serialize(Stream& s) const {
        const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

        s << version;
        unsigned char flags = 0;
        // Consistency check
        if (fAllowWitness) {
            /* Check whether witnesses need to be serialized. */
            if (HasWitness()) {
                flags |= 1;
            }
        }
        if (flags) {
            /* Use extended format in case witnesses are to be serialized. */
            std::vector<txin> vinDummy;
            s << vinDummy;
            s << flags;
        }
        s << vin;
        s << vout;
        if (flags & 1) {
            for (size_t i = 0; i < vin.size(); i++) {
                s << vin[i].scriptWit;
            }
        }
        s << locktime;
    }

    std::string ToString() const {
        std::string str;
        str += "tx(hash=" + hash.ToString().substr(0,10) + ", ver=" + std::to_string(version) + ", vin.size=" + std::to_string(vin.size()) + ", vout.size=" + std::to_string(vout.size()) + ", locktime=" + std::to_string(locktime) + ")\n";
        for (const auto& tx_in : vin)
            str += "    " + tx_in.ToString() + "\n";
#ifndef TINY_NOUTILSTRENC
        for (const auto& tx_in : vin)
            str += "    " + tx_in.scriptWitString() + "\n";
#endif
        for (const auto& tx_out : vout)
            str += "    " + tx_out.ToString() + "\n";
        return str;
    }

    inline int64_t GetWeight() const {
        #define WITNESS_SCALE_FACTOR 4
        return GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    }
#endif
};

}

#endif // BITCOIN_TINYTX_H
