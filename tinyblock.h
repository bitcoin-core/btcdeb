// Copyright (c) 2018 Karl-Johan Alm <kalle.alm@gmail.com>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TINYBLOCK_H
#define BITCOIN_TINYBLOCK_H

#include <uint256.h>
#include <tinytx.h>

namespace tiny {

struct block_header {
    int32_t version = 0;
    uint256 prev_blk;
    uint256 merkle_root;
    uint32_t time = 0;
    uint32_t bits = 0;
    uint32_t nonce = 0;

#ifndef TINY_NOSERIALIZE
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(prev_blk);
        READWRITE(merkle_root);
        READWRITE(time);
        READWRITE(bits);
        READWRITE(nonce);
    }
#endif

#ifndef TINY_NOHASH
    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }
#endif
};

struct block: public block_header {
    std::vector<tx> vtx;
    block() {}
    block(const block_header& header) : block_header(header) {}

#ifndef TINY_NOSERIALIZE
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(block_header, *this);
        READWRITE(vtx);
    }
#endif
};

} // namespace tiny

#endif // BITCOIN_TINYBLOCK_H
