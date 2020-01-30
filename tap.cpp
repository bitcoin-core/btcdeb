#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_recovery.h>

#include <support/allocators/secure.h>

#include <tinyformat.h>

#include <cliargs.h>

#include <value.h>

#include <instance.h>

#include <functions.h>

#include <config/bitcoin-config.h>

#include <hash.h>

#define abort(msg...) do { fprintf(stderr, msg); fputc('\n', stderr); exit(1); } while(0)
#define HEXC(v) HexStr(v).c_str()

static secp256k1_context* secp256k1_context_sign = nullptr;

static void ECC_Start();
static void ECC_Stop();

static const CHashWriter HasherTapSighash = TaggedHash("TapSighash");
static const CHashWriter HasherTapLeaf = TaggedHash("TapLeaf");
static const CHashWriter HasherTapBranch = TaggedHash("TapBranch");
static const CHashWriter HasherTapTweak = TaggedHash("TapTweak");

constexpr const char* DEFAULT_ADDR_PREFIX = "sb"; // TODO: switch to bcrt once WIP proposal merged

typedef std::vector<uint8_t> Item;

static Item PLACEHOLDER_SIGNATURE = ParseHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");

bool quiet = false;
bool pipe_in = false;  // xxx | btcdeb
bool pipe_out = false; // btcdeb xxx > file

inline bool checkenv(const std::string& flag, bool fallback = false) {
    const auto& v = std::getenv(flag.c_str());
    return v ? strcmp("0", v) : fallback;
}

struct TapNode {
    size_t m_index;
    uint256 m_hash;
    TapNode* m_parent{nullptr};
    TapNode(size_t index) : m_index(index) {}
    virtual ~TapNode() {}
    virtual std::string ToString() const { return strprintf("#%zu", m_index); }
    virtual void Prove(const TapNode* child, Item& proof) const {
        abort("this node type cannot make proofs");
    }
};

struct TapBranch : public TapNode {
    TapNode* m_l;
    TapNode* m_r;
    size_t m_index_r;
    virtual ~TapBranch() {
        if (m_l) delete m_l;
        if (m_r) delete m_r;
    }
    virtual std::string ToString() const override { return strprintf("(%s, %s)", m_l->ToString(), m_r->ToString()); }
    TapBranch(TapNode* l, TapNode* r) : TapNode(l->m_index), m_l(l), m_r(r), m_index_r(r->m_index) {
        if (l->m_parent) abort("left node has a parent already");
        if (r->m_parent) abort("right node has a parent already");
        l->m_parent = r->m_parent = this;
        auto hasher = HasherTapBranch;
        auto h_l = m_l->m_hash;
        auto h_r = m_r->m_hash;
        if (std::lexicographical_compare(h_r.begin(), h_r.end(), h_l.begin(), h_l.end())) {
            auto tmp = h_l; h_l = h_r; h_r = tmp;
        }
        hasher << h_l << h_r;
        m_hash = hasher.GetSHA256();
    }
    virtual void Prove(const TapNode* child, Item& proof) const override {
        uint256 hash;
        if (child == m_l) {
            hash = m_r->m_hash;
        } else if (child == m_r) {
            hash = m_l->m_hash;
        } else abort("TapBranch::Prove failed to prove missing child %s (this branch has %s and %s)\n", child->ToString().c_str(), m_l->ToString().c_str(), m_r->ToString().c_str());
        proof.insert(proof.end(), hash.begin(), hash.end());
        if (m_parent) m_parent->Prove(this, proof);
    }
};

struct TapLeaf : public TapNode {
    TapLeaf(size_t index, const uint256& hash) : TapNode(index) { m_hash = hash; }
    TapLeaf(size_t index, const CScript& script) : TapNode(index) {
        auto hasher = HasherTapLeaf;
        hasher << static_cast<uint8_t>(0xc0) << script;
        m_hash = hasher.GetSHA256();
    }
};

int main(int argc, char* const* argv)
{
    ECC_Start();

    pipe_in = !isatty(fileno(stdin)) || std::getenv("DEBUG_SET_PIPE_IN");
    pipe_out = !isatty(fileno(stdout)) || std::getenv("DEBUG_SET_PIPE_OUT");
    if (pipe_in || pipe_out) btc_logf = btc_logf_dummy;

    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("version", 'v', no_arg);
    ca.add_option("addrprefix", 'p', req_arg);
    ca.add_option("tx", 'x', req_arg);
    ca.add_option("txin", 'i', req_arg);
    ca.add_option("privkey", 'k', req_arg);
    ca.add_option("sig", 's', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q') || pipe_in || pipe_out;
    if (quiet) btc_logf = btc_logf_dummy;

    if (ca.m.count('v')) {
        printf("tap (\"The Bitcoin Debugger Taproot Utility\") version %d.%d.%d\n", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION);
        return 0;
    } else if (ca.m.count('h') || ca.l.size() < 3) {
        fprintf(stderr, "Syntax: %s [-v|--version] [-q|--quiet] [--addrprefix=sb|-psb] [--tx=<hex>|-x<hex>] [--txin=<hex>|-i<hex>] [--privkey=<key>|-k<key>] [--sig=<hex>|-s<hex>] <internal_pubkey> <script_count> <script1> <script2> ... [<spend index or sig> [<spend arg1> [<spend arg2> [...]]]]\n", argv[0]);
        fprintf(stderr, "If spend index and args are omitted, and no transaction data is provided, this generates a tweaked pubkey for funding.\n");
        fprintf(stderr, "If spend index and args are omitted, but transaction data is provided, this generates witness data for a Taproot spend and inserts this into the spending transaction.\n");
        fprintf(stderr, "If spend index and args are included, this generates the spending witness based on the given input.\n");
        fprintf(stderr, "If spend index, args, and transaction data are all included, the spending witness is inserted into the transaction.\n");
        fprintf(stderr, "A signature is generated if --privkey is given. If a signature is provided via the --sig argument, it is used as is.\n");
        fprintf(stderr, "The address prefix refers to the bech32 human readable part; this defaults to '%s'\n", DEFAULT_ADDR_PREFIX);
        return 0;
    }
    btc_logf("tap %d.%d.%d -- type `%s -h` for help\n", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION, argv[0]);
    fprintf(stderr, "WARNING: This is experimental software. Do not use this with real bitcoin, or you will most likely lose them all. You have been w a r n e d.\n");

    if (!pipe_in) {
        // temporarily defaulting all to ON
        if (checkenv("DEBUG_SIGHASH")) btc_sighash_logf = btc_logf_stderr;
        if (checkenv("DEBUG_SIGNING", true)) btc_sign_logf = btc_logf_stderr;
        if (checkenv("DEBUG_SEGWIT", true))  btc_segwit_logf = btc_logf_stderr;
        if (checkenv("DEBUG_TAPROOT", true)) btc_taproot_logf = btc_logf_stderr;
        btc_logf("LOG:");
        if (btc_enabled(btc_sighash_logf)) btc_logf(" sighash");
        if (btc_enabled(btc_sign_logf)) btc_logf(" sign");
        if (btc_enabled(btc_segwit_logf)) btc_logf(" segwit");
        if (btc_enabled(btc_taproot_logf)) btc_logf(" taproot");
        btc_logf("\n");
    }

    Item premade_sig;
    Item privkey;
    bech32_hrp = ca.m.count('p') ? ca.m['p'] : DEFAULT_ADDR_PREFIX;

    bool have_txs = false;
    if (ca.m.count('x') + ca.m.count('i') == 1) abort("provide either both --txin and --tx, or neither");
    if (ca.m.count('x')) {
        have_txs = true;
        if (!instance.parse_transaction(ca.m['x'].c_str(), false)) {
            abort("failed to parse transaction");
        }
        if (!instance.parse_input_transaction(ca.m['i'].c_str())) {
            abort("failed to parse input transaction");
        }
        btc_logf("targeting transaction vin at index #%lld\n", instance.tx_internal_vin_index_of_txin);
    }

    if (ca.m.count('k')) {
        Value wif(ca.m['k'].c_str());
        if (wif.type == Value::T_STRING) {
            // WIF encoding?
            wif.do_decode_wif();
        }
        if (wif.type != Value::T_DATA) {
            abort("failed to parse private key (not raw data, and not WIF encoded): %s", ca.m['k'].c_str());
        }
        privkey = wif.data;
        if (privkey.size() != 32) {
            abort("invalid private key (wrong size: %zu, must be 32)", privkey.size());
        }
    }

    if (ca.m.count('s')) {
        if (!TryHex(ca.m['s'], premade_sig)) {
            abort("failed to parse signature: %s", ca.m['s'].c_str());
        }
        if (privkey.size()) abort("cannot use --privkey and --sig simultaneously");
    }

    std::string internal_pubkey_str = ca.l[0];
    Item internal_pubkey;
    if (!TryHex(internal_pubkey_str, internal_pubkey)) {
        abort("invalid internal pubkey %s: not parsable hex value", internal_pubkey_str.c_str());
    }
    if (internal_pubkey.size() != 32) {
        abort("invalid internal pubkey %s -> %s: length %zu invalid (must be 32 bytes)", internal_pubkey_str.c_str(), HEXC(internal_pubkey), internal_pubkey.size());
    }
    btc_logf("Internal pubkey: %s\n", HEXC(internal_pubkey));
    uint256 internal_pubkey_u256 = uint256(internal_pubkey);

    size_t script_count = atol(ca.l[1]);
    if (script_count < 1 || script_count > 1024) {
        abort("invalid script count: %zu (allowed range 1..1024)", script_count);
    }
    if (ca.l.size() < 2 + script_count) {
        abort("missing scripts (count %zu but only %zu arguments)", script_count, ca.l.size() - 2);
    }

    size_t sai = 2 + script_count;
    size_t sargc = sai < ca.l.size() ? ca.l.size() - sai : 0;
    size_t spending_index = (size_t)-1;
    bool is_taproot = false, is_tapscript = false;
    std::vector<Item> taproot_input_stack; // ScriptWitness variant
    CScript taproot_inputs;                // manual variant
    size_t witness_stack_count = 0;
    if (have_txs && sargc == 0) {
        btc_logf("- no spend arguments; TAPROOT mode\n");
        is_taproot = true;
    }
    if (sargc > 0) {
        btc_logf("%zu spending argument%s present\n", sargc, sargc == 1 ? "" : "s");
        // spend mode -- if 1 single argument, it's taproot, and the argument is the signature
        btc_logf("- 1+ spend arguments; TAPSCRIPT mode\n");
        is_tapscript = true;
        spending_index = atol(ca.l[sai++]);
        if (spending_index >= script_count) {
            abort("invalid script index: %zu must be within range [0..%zu]\n", spending_index, script_count = 1);
        }
        while (sai < ca.l.size()) {
            if (std::string(ca.l[sai]) == "%SIG%") {
                taproot_input_stack.push_back(PLACEHOLDER_SIGNATURE);
                taproot_inputs << PLACEHOLDER_SIGNATURE;
                btc_logf("  #%zu: <placeholder signature>\n", witness_stack_count);
            } else {
                auto v = Value(ca.l[sai]).data_value();
                taproot_input_stack.push_back(v);
                taproot_inputs << v;
                btc_logf("  #%zu: %s\n", witness_stack_count, HEXC(v));
            }
            ++sai;
            ++witness_stack_count;
        }
    }

    std::vector<CScript> scripts;
    btc_logf("%zu scripts:\n", script_count);
    for (size_t i = 0; i < script_count; ++i) {
        Item scriptData = Value(ca.l[2 + i]).data_value();
        CScript script = CScript(scriptData.begin(), scriptData.end());
        if (!script.HasValidOps()) {
            abort("invalid script #%zu: %s", i, HEXC(scriptData));
        }
        if (!quiet) {
            btc_logf("- #%zu: %s\n", i, HEXC(script));
        }
        scripts.emplace_back(script);
    }

    // if we are doing a tapscript spend, we can add the program now that we know it
    Item spending_script;
    if (is_tapscript) {
        spending_script = Item(scripts[spending_index].begin(), scripts[spending_index].end());
    }

    // generate tapscript commitment (always)
    std::vector<TapNode*> branches;
    TapLeaf* pending = nullptr;
    TapLeaf* spending_leaf = nullptr;
    for (size_t i = 0; i < script_count; ++i) {
        TapLeaf* leaf = new TapLeaf(i, scripts[i]);
        btc_logf("Script #%zu leaf hash = TapLeaf<<0xc0 || %s>>\n → %s\n", i, HexStr(scripts[i]).c_str(), HexStr(leaf->m_hash).c_str());
        if (is_tapscript && i == spending_index) spending_leaf = leaf;
        if (pending) {
            // we've got a pair
            branches.push_back(new TapBranch(pending, leaf));
            btc_logf("Branch (%s, #%zu)\n → %s\n", pending->ToString().c_str(), i, HexStr(branches.back()->m_hash).c_str());
            pending = nullptr;
        } else {
            pending = leaf;
        }
    }
    if (pending) {
        // we have [a,b] [c,d] and pending e
        // we extend [c,d] to be [[c,d], e]
        TapNode* rightmost = branches.back();
        branches.pop_back();
        branches.push_back(new TapBranch(rightmost, pending));
        btc_logf("Leftover node %s baked into right-most (last) tree %s\n → %s\n", pending->ToString().c_str(), rightmost->ToString().c_str(), HexStr(branches.back()->m_hash).c_str());
        pending = nullptr;
    }
    // now we pair things together until we have a root node
    while (branches.size() > 1) {
        // iterate
        for (size_t i = 0; i < branches.size() - 1; ++i) {
            TapNode* l = branches[i];
            TapNode* r = branches[i + 1];
            branches.erase(branches.begin() + i);
            branches[i] = new TapBranch(l, r);
            btc_logf("Merged at #%zu: %s and %s = %s\n → %s\n", i, l->ToString().c_str(), r->ToString().c_str(), branches[i]->ToString().c_str(), HexStr(branches[i]->m_hash).c_str());
        }
    }

    if (branches.size() != 1) {
        abort("Unable to generate tapscript commitment tree (branch size did not end up at 1, it is %zu)", branches.size());
    }

    // control block (if spending) -- note that we put the leaf version and negation bit in last, as we don't know if the pubkey was negated yet
    Item ctl = internal_pubkey;
    if (is_tapscript) {
        btc_logf("Control object = (leaf), (internal pubkey = %s), ...\n", HEXC(internal_pubkey));
        if (!spending_leaf) {
            abort("Internal error: Spending leaf was not derived (this is a bug; please report)");
        }
        spending_leaf->m_parent->Prove(spending_leaf, ctl);
        btc_logf("... with proof -> %s\n", HEXC(ctl));
    }

    // now TapTweak <pubkey> <root>
    TapNode* root = branches[0];
    auto hasher = HasherTapTweak;
    hasher << internal_pubkey_u256 << root->m_hash;
    auto tweak = hasher.GetSHA256();
    btc_logf("Tweak value = %s\n", HEXC(tweak));
    // now tweak the pubkey
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_sign, &pubkey, internal_pubkey.data())) {
        abort("invalid input: pubkey invalid (parse failed)");
    }
    int is_negated;
    if (!secp256k1_xonly_pubkey_tweak_add(secp256k1_context_sign, &pubkey, &is_negated, tweak.begin())) {
        abort("failure: secp256k1_xonly_pubkey_tweak_add call failed");
    }
    Item serialized_pk;
    serialized_pk.resize(32);
    if (!secp256k1_xonly_pubkey_serialize(secp256k1_context_sign, serialized_pk.data(), &pubkey)) {
        abort("failed to serialize pubkey");
    }
    btc_logf("Tweaked pubkey = %s (%snegated)\n", HEXC(serialized_pk), is_negated ? "" : "not ");

    // if we have a txin, we can now verify that our pubkey matches the pubkey in the output
    if (have_txs) {
        auto spk = instance.txin->vout[instance.txin_vout_index_spent_by_tx].scriptPubKey;
        if (spk.size() < serialized_pk.size()) {
            abort("pubkey mismatch: input transaction's vout[%lld].scriptPubKey = %s, but our pubkey = %s\n", instance.txin_vout_index_spent_by_tx, HEXC(spk), HEXC(serialized_pk));
        }
        auto cmp = Item(spk.end() - serialized_pk.size(), spk.end());
        if (cmp != serialized_pk) {
            abort("pubkey mismatch: input transaction's vout[%lld].scriptPubKey %s does not end (%s) with our pubkey %s\n", instance.txin_vout_index_spent_by_tx, HEXC(spk), HEXC(cmp), HEXC(serialized_pk));
        }
        btc_logf("Pubkey matches the scriptPubKey of the input transaction's output #%lld\n", instance.txin_vout_index_spent_by_tx);
    }

    Value v(serialized_pk);
    v.do_bech32enc();

    printf("Resulting Bech32 address: %s\n", v.str_value().c_str());

    if (is_taproot &&privkey.size() != 0) {
        if (!secp256k1_xonly_seckey_tweak_add(secp256k1_context_sign, privkey.data(), tweak.begin())) {
            abort("failure: secp256k1_xonly_seckey_tweak_add call failed");
        }
        btc_logf("tweaked privkey -> %s\n", HEXC(privkey));

        Value v(privkey);
        v.do_get_xpubkey();
        if (v.data_value() != serialized_pk) {
            abort("the provided private key has a corresponding public key %s\nhowever, the tweaked public key for this output is %s", HEXC(v.data), HEXC(serialized_pk));
        }
        btc_logf("The given private key matches the tweaked public key\n");
    }

    if (is_tapscript) {
        // we can now finally put in the leaf/negation bit in the control object
        uint8_t ctl_ln = is_negated ? 0xc1 : 0xc0;
        ctl.insert(ctl.begin(), &ctl_ln, &ctl_ln + 1);
        btc_logf("Final control object = %s\n", HEXC(ctl));
    }

    // if we have transaction data, replace the witness stack for the appropriate input
    if (have_txs) {
        if (premade_sig.size()) {
            // insert signature
            taproot_input_stack.insert(taproot_input_stack.begin(), premade_sig);
        } else if (privkey.size() == 0) {
            // append a placeholder sig to the witness stack, or the instance system won't recognize the output type
            taproot_input_stack.insert(taproot_input_stack.begin(), PLACEHOLDER_SIGNATURE);
        }

        if (is_tapscript) {
            // append script to taproot inputs
            taproot_input_stack.push_back(spending_script);
            taproot_inputs << spending_script;
            btc_logf("Adding selected script to taproot inputs: %s\n → %s\n", HEXC(scripts[spending_index]), HEXC(taproot_inputs));
            ++witness_stack_count;
            // append control object
            btc_logf("appending control object to taproot input stack: %s\n", HEXC(ctl));
            taproot_input_stack.push_back(ctl);
            taproot_inputs << ctl;
            ++witness_stack_count;
            btc_logf("Tapscript spending witness: [\n");
            for (auto& x : taproot_input_stack) btc_logf(" \"%s\",\n", HEXC(x));
            btc_logf("]\n");
        }

        CMutableTransaction mtx(*instance.tx);
        mtx.vin[instance.tx_internal_vin_index_of_txin].scriptWitness.stack = taproot_input_stack;
        instance.tx = MakeTransactionRef(mtx);

        instance.configure_tx_txin();
        instance.execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
        instance.execdata.m_codeseparator_pos_init = true;

        const uint256 sighash = instance.calc_sighash();
        btc_logf("sighash (little endian) = %s\n", HEXC(sighash));

        if (privkey.size()) {
            secp256k1_schnorrsig sig;
            secp256k1_xonly_pubkey pubkey;
            if (!secp256k1_xonly_pubkey_create(secp256k1_context_sign, &pubkey, privkey.data())) {
                abort("failed to derive pubkey");
            }

            if (!secp256k1_schnorrsig_sign(secp256k1_context_sign, &sig, sighash.begin(), privkey.data(), NULL, NULL)) {
                abort("failed to create signature");
            }
            if (!secp256k1_schnorrsig_verify(secp256k1_context_sign, &sig, sighash.begin(), &pubkey)) {
                abort("failed to verify signature");
            }
            Item data;
            data.resize(64);
            if (!secp256k1_schnorrsig_serialize(secp256k1_context_sign, data.data(), &sig)) {
                abort("failed to serialize signature");
            }
            btc_logf("signature: %s\n", HEXC(data));
            taproot_input_stack.insert(taproot_input_stack.begin(), data);

            mtx.vin[instance.tx_internal_vin_index_of_txin].scriptWitness.stack = taproot_input_stack;
            instance.tx = MakeTransactionRef(mtx);
        } else if (premade_sig.size() == 0) {
            printf("NOTE: there is a placeholder signature at the end of the witness data for the resulting transaction below; this must be replaced with a 64 byte signature for the sighash given above\n");
        }

        mtx.vin[instance.tx_internal_vin_index_of_txin].scriptWitness.stack = taproot_input_stack;
        instance.tx = MakeTransactionRef(mtx);

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *instance.tx;
        printf("Resulting transaction: %s\n", HEXC(ssTx));
    }

    ECC_Stop();
}

static void GetRandBytes(unsigned char* buf, int num)
{
    // TODO: Make this more cross platform
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        abort("unable to open /dev/urandom for GetRandBytes(): sorry! btcdeb does not currently work on your operating system for signature signing\n");
        exit(1);
    }
    if (fread(buf, 1, num, f) != num) {
        abort("unable to read from /dev/urandom\n");
        exit(1);
    }
    fclose(f);
}

static void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

static void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}