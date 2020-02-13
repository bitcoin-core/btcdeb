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
    mutable bool SymbolicOutputs{false};
    typedef CPubKey Key;

    bool ToString(const Key& key, std::string& str) const {
        str = SymbolicOutputs && Symbols.count(key) ? Symbols.at(key) : key.ToString();
        return true;
    }

    template<typename I>
    bool FromString(I first, I last, Key& key) const {
        if (std::distance(first, last) == 0 || std::distance(first, last) > 66) {
            return false;
        }
        if (std::distance(first, last) < 17) {
            // symbolic
            do {
                symkeys++;
                uint256 u = ArithToUint256(symkeys);
                std::vector<uint8_t> k;
                k.push_back(0x03);
                k.insert(k.end(), u.begin(), u.end());
                key = CPubKey(k);
            } while (!key.IsFullyValid());
            auto s = std::string(first, last);
            KeyMap[s] = key;
            Symbols[key] = s;
            return true;
        }
        key = CPubKey(ParseHex(first));
        return key.IsFullyValid();
    }

    std::vector<unsigned char> ToPKBytes(const Key& key) const {
        return std::vector<unsigned char>(key.begin(), key.end());
    }

    std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        auto pkh = key.GetID();
        return std::vector<unsigned char>(pkh.begin(), pkh.end());
    }

    mutable arith_uint256 symkeys;
    mutable std::map<std::string,CPubKey> KeyMap;
    mutable std::map<CPubKey,std::string> Symbols;
};

extern const CompilerContext COMPILER_CTX;

bool Compile(const std::string& policy, miniscript::NodeRef<CompilerContext::Key>& ret, double& avgcost);

std::string Expand(std::string str);
std::string Abbreviate(std::string str);

std::string Disassemble(const CScript& script);

#endif
