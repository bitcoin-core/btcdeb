// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_
#define _BITCOIN_SCRIPT_MINISCRIPT_COMPILER_H_

#include <script/miniscript.h>

#include <pubkey.h>
#include <arith_uint256.h>

#include <string>

struct CompilerContext {
    typedef CPubKey Key;

    mutable arith_uint256 symkeys;
    mutable std::map<std::string,CPubKey> keymap;
    mutable std::map<CPubKey,std::string> symbols;
    mutable bool symbolic_outputs{false};
    mutable std::map<CKeyID, Key> pkh_map;
    mutable std::set<std::vector<uint8_t>> fake_sigs;

    bool ToString(const Key& key, std::string& str) const {
        str = symbolic_outputs && symbols.count(key) ? symbols.at(key) : key.ToString();
        return true;
    }

    template<typename I>
    bool FromString(I first, I last, Key& key) const {
        if (std::distance(first, last) == 0 || std::distance(first, last) > 66) {
            return false;
        }
        if (std::distance(first, last) < 17) {
            // symbolic
            auto s = std::string(first, last);
            if (keymap.count(s)) {
                key = keymap.at(s);
                return true;
            }
            do {
                symkeys++;
                uint256 u = ArithToUint256(symkeys);
                std::vector<uint8_t> k;
                k.push_back(0x03);
                k.insert(k.end(), u.begin(), u.end());
                key = CPubKey(k);
            } while (!key.IsFullyValid());
            keymap[s] = key;
            pkh_map[key.GetID()] = key;
            symbols[key] = s;
            return true;
        }
        key = CPubKey(ParseHex(first));
        if (!key.IsFullyValid()) return false;
        pkh_map[key.GetID()] = key;
        return true;
    }

    std::vector<unsigned char> ToPKBytes(const Key& key) const {
        return std::vector<unsigned char>(key.begin(), key.end());
    }

    std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        auto pkh = key.GetID();
        return std::vector<unsigned char>(pkh.begin(), pkh.end());
    }

    template<typename I>
    bool FromPKBytes(I first, I last, Key& key) const {
        key.Set(first, last);
        if (!key.IsFullyValid()) return false;
        pkh_map[key.GetID()] = key;
        return true;
    }

    template<typename I>
    bool FromPKHBytes(I first, I last, Key& key) const {
        assert(last - first == 20);
        CKeyID keyid;
        std::copy(first, last, keyid.begin());
        auto it = pkh_map.find(keyid);
        if (it == pkh_map.end()) {
            // we don't have it, so let's make one and mark it as unknown
            printf("unknown key ID %s: returning fake key\n", HexStr(keyid.begin(), keyid.end()).c_str());
            do {
                symkeys++;
                uint256 u = ArithToUint256(symkeys);
                std::vector<uint8_t> k;
                k.push_back(0x03);
                k.insert(k.end(), u.begin(), u.end());
                key = CPubKey(k);
            } while (!key.IsFullyValid());
            auto s = std::string(first, last);
            keymap[s] = key;
            pkh_map[key.GetID()] = key;
            symbols[key] = s;
            return true;
        }
        key = it->second;
        return true;
    }
};

extern const CompilerContext COMPILER_CTX;

bool Compile(const std::string& policy, miniscript::NodeRef<CompilerContext::Key>& ret, double& avgcost);

std::string Expand(std::string str);
std::string Abbreviate(std::string str);

std::string Disassemble(const CScript& script);

#endif
