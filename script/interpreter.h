// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <script/script_error.h>
#include <primitives/transaction.h>

#include <vector>
#include <stdint.h>

class CPubKey;
class XOnlyPubKey;
class CScript;
class CTransaction;
class CTxOut;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,

    SIGHASH_DEFAULT = 0, //!< Taproot only; implied when sighash byte is missing, and equivalent to SIGHASH_ALL
    SIGHASH_OUTPUT_MASK = 3,
    SIGHASH_INPUT_MASK = 0x80,
};

/** Script verification flags.
 *
 *  All flags are intended to be soft forks: the set of acceptable scripts under
 *  flags (A | B) is a subset of the acceptable scripts under flag (A).
 */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    // NOPs that have associated forks to give them new meaning (CLTV, CSV)
    // are not subject to this rule.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS = (1U << 11),

    // Making v1-v16 witness program non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in segregated witness scripts must be compressed
    //
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),

    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    //
    SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 16),

    // Taproot/Tapscript validation (BIPs 341 & 342)
    //
    SCRIPT_VERIFY_TAPROOT = (1U << 17),

    // Making unknown Taproot leaf versions non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1U << 18),

    // Making the use of (unknown) annexes non-standard (currently no annexes are known)
    //
    SCRIPT_VERIFY_DISCOURAGE_UNKNOWN_ANNEX = (1U << 19),

    // Making unknown OP_SUCCESS non-standard
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = (1U << 20),

    // Making unknown public key versions (in BIP 342 scripts) non-standard
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1U << 21),
};

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror);

struct PrecomputedTransactionData
{
    //! Single-SHA256 versions
    uint256 m_prevouts_hash, m_sequences_hash, m_outputs_hash, m_amounts_spent_hash;
    bool m_amounts_spent_ready = false;

    //! Double-SHA256 versions
    uint256 hashPrevouts, hashSequence, hashOutputs;
    bool ready = false;
    std::vector<CTxOut> m_spent_outputs;

    PrecomputedTransactionData() = default;

    template <class T>
    void Init(const T& tx, std::vector<CTxOut> spent_outputs);

    template <class T>
    explicit PrecomputedTransactionData(const T& tx);
};

enum class SigVersion
{
    BASE = 0,        //!< Bare scripts and P2SH redeemscripts; see BIP 16
    WITNESS_V0 = 1,  //!< Witness v0 (P2WPKH and P2WSH); see BIP 141
    TAPROOT = 2,     //!< Witness v1 with non-P2SH 32 byte program (Taproot), key path spending; see BIP 341
    TAPSCRIPT = 3,   //!< Witness v1 with non-P2SH 32 byte program (Taproot), script path spending, leaf version 0xc0 (Tapscript); see BIP 342
};

struct ScriptExecutionData
{
    //! Whether m_tapleaf_hash is initialized.
    bool m_tapleaf_hash_init = false;
    //! The tapleaf hash.
    uint256 m_tapleaf_hash;

    //! Whether m_codeseparator_pos is initialized.
    bool m_codeseparator_pos_init = false;
    //! Opcode position of the last executed OP_CODESEPARATOR (or -1 if none executed).
    uint32_t m_codeseparator_pos;

    //! Whether m_annex_present and m_annex_hash are initialized.
    bool m_annex_init = false;
    //! Whether an annex is present.
    bool m_annex_present;
    //! Hash of the annex data.
    uint256 m_annex_hash;

    /** Whether m_validation_weight_left is initialized. */
    bool m_validation_weight_left_init = false;
    /** How much validation weight is left (decremented for every successful signature check). */
    int64_t m_validation_weight_left;
};

/** Signature hash sizes */
static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;
static constexpr size_t WITNESS_V1_TAPROOT_SIZE = 32;


static constexpr uint8_t TAPROOT_LEAF_MASK = 0xfe;
static constexpr uint8_t TAPROOT_LEAF_TAPSCRIPT = 0xc0;
static constexpr size_t TAPROOT_PROGRAM_SIZE = 32;
static constexpr size_t TAPROOT_CONTROL_BASE_SIZE = 33;
static constexpr size_t TAPROOT_CONTROL_NODE_SIZE = 32;
static constexpr size_t TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
static constexpr size_t TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr);

template <class T>
bool SignatureHashTap(uint256& hash_out, const ScriptExecutionData& execdata, const T& tx_to, unsigned int in_pos, uint8_t hash_type, SigVersion sigversion, const PrecomputedTransactionData& cache);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return false;
    }

    virtual bool CheckSigSchnorr(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, SigVersion sigversion, const ScriptExecutionData& execdata) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual bool CheckSequence(const CScriptNum& nSequence) const
    {
         return false;
    }

    virtual ~BaseSignatureChecker() {}
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const T* txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;

protected:
    virtual bool VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
    virtual bool VerifySchnorrSignature(const std::vector<unsigned char>& sig, const XOnlyPubKey& pubkey, const uint256& sighash) const;

public:
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckSigSchnorr(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, SigVersion sigversion, const ScriptExecutionData& execdata) const override;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
};

using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;

/** A data type to abstract out the condition stack during script execution.
 *
 * Conceptually it acts like a vector of booleans, one for each level of nested
 * IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
 * each.
 *
 * The elements on the stack cannot be observed individually; we only need to
 * expose whether the stack is empty and whether or not any false values are
 * present at all. To implement OP_ELSE, a toggle_top modifier is added, which
 * flips the last value without returning it.
 *
 * This uses an optimized implementation that does not materialize the
 * actual stack. Instead, it just stores the size of the would-be stack,
 * and the position of the first false value in it.
 */
class ConditionStack {
private:
    //! A constant for m_first_false_pos to indicate there are no falses.
    static constexpr uint32_t NO_FALSE = std::numeric_limits<uint32_t>::max();

    //! The size of the implied stack.
    uint32_t m_stack_size = 0;
    //! The position of the first false value on the implied stack, or NO_FALSE if all true.
    uint32_t m_first_false_pos = NO_FALSE;

public:
    bool empty() { return m_stack_size == 0; }
    bool all_true() { return m_first_false_pos == NO_FALSE; }
    void push_back(bool f)
    {
        if (m_first_false_pos == NO_FALSE && !f) {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            m_first_false_pos = m_stack_size;
        }
        ++m_stack_size;
    }
    void pop_back()
    {
        assert(m_stack_size > 0);
        --m_stack_size;
        if (m_first_false_pos == m_stack_size) {
            // When popping off the first false value, everything becomes true.
            m_first_false_pos = NO_FALSE;
        }
    }
    void toggle_top()
    {
        assert(m_stack_size > 0);
        if (m_first_false_pos == NO_FALSE) {
            // The current stack is all true values; the first false will be the top.
            m_first_false_pos = m_stack_size - 1;
        } else if (m_first_false_pos == m_stack_size - 1) {
            // The top is the first false value; toggling it will make everything true.
            m_first_false_pos = NO_FALSE;
        } else {
            // There is a false value, but not on top. No action is needed as toggling
            // anything but the first false value is unobservable.
        }
    }
    int println() {
        if (m_stack_size == 0) printf("- empty stack -\n");

        int i = 0;
        bool curr = m_first_false_pos == NO_FALSE;
        for (int j = m_stack_size - 1; j >= 0; j--) {
            i++;
            printf("<%02d>\t%02x\n", i, (unsigned char)curr);
            curr |= (m_first_false_pos == j);
        }

        return 0;
    }
};

struct ScriptExecutionEnvironment {
    CScript script;
    CScript::const_iterator pend;
    CScript::const_iterator pbegincodehash;
    opcodetype opcode;
    std::vector<uint8_t> vchPushValue;
    ConditionStack vfExec;
    std::vector<std::vector<uint8_t>> altstack;
    int nOpCount;
    bool fRequireMinimal;
    std::vector<std::vector<unsigned char> >& stack;
    unsigned int flags;
    const BaseSignatureChecker& checker;
    SigVersion sigversion;
    ScriptError* serror;
    std::map<std::vector<unsigned char>,std::vector<unsigned char>> pretend_valid_map;
    std::set<std::vector<unsigned char>> pretend_valid_pubkeys;
    ScriptExecutionEnvironment(std::vector<std::vector<unsigned char> >& stack_in, const CScript& script_in, unsigned int flags_in, const BaseSignatureChecker& checker_in);

    uint32_t opcode_pos;
    ScriptExecutionData execdata;
};

bool StepScript(ScriptExecutionEnvironment& env, CScript::const_iterator& pc, CScript* local_script = nullptr);

// made public to assist instance.cpp
bool VerifyTaprootCommitment(const std::vector<unsigned char>& control, const std::vector<unsigned char>& program, const CScript& script, uint256* tapleaf_hash);

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr, ScriptExecutionData execdata = {});
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags);

int FindAndDelete(CScript& script, const CScript& b);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
