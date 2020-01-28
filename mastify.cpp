#include <cstdio>
#include <unistd.h>

#include <value.h>
#include <merkle.h>
#include <streams.h>
#include <debugger/interpreter.h>
#include <policy/policy.h>
#include <hash.h>
#include <cliargs.h>

typedef std::vector<unsigned char> valtype;
bool piping = false;
bool quiet = false;

struct CodePath {
    CScript script;
    size_t params;
    size_t stack_size;
    std::vector<bool> active;
    std::vector<size_t> anti_indices;
    size_t path_index;
    bool is_active() { return active.size() == 0 || active.back(); }
    void swap_active() { if (!active.size()) active.push_back(true); active[active.size()-1] = !active[active.size()-1]; }
    void pop_active() { if (!active.size()) { fprintf(stderr, "error: ELSE without IF\n"); exit(1); } active.pop_back(); }
    CodePath(CScript script_in = CScript(), size_t params_in = 0, size_t stack_size_in = 0, std::vector<bool> active_in = std::vector<bool>())
    : script(script_in)
    , params(params_in)
    , stack_size(stack_size_in)
    , active(active_in)
    , path_index(0)
    {}
    CodePath(std::vector<Value>& pubkeys) : CodePath()
    {
        // we want to create a series of OP_CHECKSEQUENCE{VERIFY} calls, one per
        // pubkey, the final one missing the VERIFY part
        auto& noverify = pubkeys.back();
        for (auto& key : pubkeys) {
            script << key.data_value() << (noverify == key ? OP_CHECKSIG : OP_CHECKSIGVERIFY);
        }
        params = pubkeys.size(); // one signature per pubkey
    }
    CodePath split(CScript& left, CScript& right, size_t other_index) {
        CodePath c{script, params, stack_size, active};
        script += left;
        c.script += right;
        c.active.push_back(false);
        active.push_back(true);
        anti_indices.push_back(other_index);
        return c;
    }
    void touch(size_t spawned, size_t slain, bool debug = false, opcodetype opcode = OP_0) {
        // if (debug) printf("[%s]: (+%zu, -%zu) for %zu (%zu) -> ", GetOpName(opcode), spawned, slain, stack_size, params);
        if (stack_size < slain) {
            // need more parameters
            params += slain - stack_size;
            stack_size = slain;
        }
        stack_size = stack_size + spawned - slain;
        // if (debug) printf("%zu (%zu)\n", stack_size, params);
    }
    void add_fromaltstacks() {
        CScript prefix_script;
        for (auto i = 0; i < params; ++i) {
            prefix_script << OP_FROMALTSTACK;
        }
        script = prefix_script + script;
    }
};

std::string repeat(const char* v, size_t count, std::string separator = " ") {
    std::string res = v;
    count --;
    while (count > 0) {
        res += separator + v;
        count --;
    }
    return res;
}

void split_codepaths(std::vector<CodePath>& paths, CScript& left, CScript& right) {
    size_t len = paths.size();
    for (size_t i = 0; i < len; i++) {
        if (paths[i].is_active()) {
            paths.push_back(paths[i].split(left, right, paths.size()));
        } else {
            paths[i].active.push_back(false);
        }
    }
}

void interpret_opcode(std::vector<CodePath>& paths, opcodetype opcode) {
    // first update params
    size_t spawned, slain;
    GetStackFeatures(opcode, spawned, slain);
    if (spawned + slain) {
        // bool first = true;
        for (auto& path : paths) {
            if (path.is_active()) {
                path.touch(spawned, slain);
                // first = false;
            }
        }
    }
    switch (opcode) {
    case OP_IF:
    case OP_NOTIF: {
        int activation = opcode == OP_IF;
        CScript scripts[2];
        scripts[1 - activation] << OP_VERIFY;
        scripts[activation] << OP_NOT << OP_VERIFY;
        split_codepaths(paths, scripts[0], scripts[1]);
    } break;
    case OP_ELSE:
        for (auto& path : paths) {
            path.swap_active();
        }
        break;
    case OP_ENDIF:
        for (auto& path : paths) {
            path.pop_active();
        }
        break;
    default:
        for (auto& path : paths) {
            if (path.is_active()) {
                path.script << opcode;
            }
        }
    break;
    }
}

void update_path(size_t& idx, std::vector<CodePath>& paths, opcodetype opcode, ConditionStack& state) {
    switch (opcode) {
    case OP_IF:
    case OP_NOTIF: {
        bool passed = state.all_true();
        if (passed) {
            // iterate path index
            paths[idx].path_index++;
        } else {
            // swap to anti-index
            fprintf(stderr, "switching to alternative path from idx=%zu to idx=", idx);
            idx = paths[idx].anti_indices[paths[idx].path_index];
            fprintf(stderr, "%zu\n", idx);
        }
    } break;
    default:
        break;
    }
}

int main(int argc, char* const* argv)
{
    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("trimmable", 't', no_arg);
    ca.add_option("legacy", 'l', no_arg);
    ca.add_option("btcdeb", 'b', no_arg);
    ca.add_option("version", 'v', no_arg);
    ca.parse(argc, argv);

    if (ca.m.count('h') || ca.l.size() < 2) {
        fprintf(stderr, "syntax: %s [-v|--version] [-t|--trimmable] [-b|--btcdeb] [-l|--legacy] <script> [<arg1> [<arg2> [...]]]\n", argv[0]);
        fprintf(stderr,
            "e.g.: %s --trimmable \"[\n"
            // "   # Source: https://lists.linuxfoundation.org/pipermail/lightning-dev/2015-July/000021.html\n"
            // "   # They present HTLC's R value, or either revocation hash:\n"
            // "   # Our revocation value: 8c2574892063f995fdf756bce07f46c1a5193e54cd52837ed91e32008ccf41ac\n"
            // "   # Revocation key 1: 9b4b4ae7be32f4728ea406cf9ab8356669c86849c574b51ccf1d871779b13a22\n"
            // "   # Revocation key 2: 568b2573a69d9010c82f556f4160d5672d7877f9abebb5d401cbaa3caefdf578\n"
            // "   OP_DUP OP_HASH160 # Create a hash160 of the key\n"
            // "   OP_DUP aec8d17368a55051e3aa9cf14563a4e537a01a20 OP_EQUAL\n"
            // "   OP_TOALTSTACK OP_DUP 3b75accc015232a588750a33001827bb012f3c19 OP_EQUAL\n"
            // "   OP_FROMALTSTACK OP_ADD OP_SWAP fc2f0717a2e4bb32789f5134a5de83b83e14dc57 OP_EQUAL\n"
            // "   OP_ADD\n"
            // "   OP_IF\n"
            // "       # One hash matched, pay to them.\n"
            // "       # Input is: 0375ceeb0d9d99ff238f85aa5d18e318c7f0a84d3b7bec31a99df66df0bf887ee4\n"
            // "       OP_DROP OP_DUP OP_HASH160 879fc35b1d179d5141025b47f929e6ced5387a9f\n"
            // "   OP_ELSE\n"
            // "       # Must be us, with HTLC timed out.\n"
            // "       # HTLC absolute timeout part\n"
            // "       1515988693 OP_CHECKLOCKTIMEVERIFY OP_DROP\n"
            // "       # Verification relative timeout\n"
            // "       144 OP_CHECKSEQUENCEVERIFY OP_DROP\n"
            // "       # Input is: 020c23a5f833b3cb2a29bf81e246886e0ea098989b359c401655c96d3f1a37567a\n"
            // "       OP_DUP OP_HASH160 293073143bf24cadbc1bff9945dd6bb9c7a8900f\n"
            // "   OP_ENDIF\n"
            // "   OP_EQUALVERIFY\n"
            // "   OP_CHECKSIG\n"
            "OP_IF\n"
            "144\n"
            "OP_CHECKSEQUENCEVERIFY\n"
            "OP_DROP\n"
            "020c23a5f833b3cb2a29bf81e246886e0ea098989b359c401655c96d3f1a37567a\n"
            "OP_ELSE\n"
            "568b2573a69d9010c82f556f4160d5672d7877f9abebb5d401cbaa3caefdf578\n"
            "OP_ENDIF\n"
            "OP_CHECKSIG\n"
            "]\"\n", argv[0]
        );
        fprintf(stderr,
            "mastify works in two modes:\n"
            "- general mode, which simply gives you the possible outcomes and scripts, as well as the merkle tree; this is the behavior when no arguments are provided to the input\n"
            "- execution mode, which gives you the solution to spending an existing mastified script; this is the behavior when 1 or more arguments are provided\n"
        );
        return 1;
    }
    bool legacy = 0 < ca.m.count('l');
    bool btcdeb = 0 < ca.m.count('b');
    bool trimmable = 0 < ca.m.count('t');
    bool fast = !legacy;
    piping = btcdeb || !isatty(fileno(stdin));
    if (piping) btc_logf = btc_logf_dummy;
    quiet = ca.m.count('q') || piping;

    std::vector<Value> args;
    std::vector<CodePath> paths;
    size_t current_path;
    bool selected_path;

    Value script(ca.l[0]);
    for (int i = 1; i < ca.l.size(); ++i) {
        args.emplace_back(ca.l[i]);
    }
    // printf("script: %s\n", script.hex_str().c_str());
    CScript spt = CScript(script.data.begin(), script.data.end());
    // determine conditional branches, and parameter counts
    paths.emplace_back();
    CScript::const_iterator it = spt.begin();
    opcodetype opcode;
    valtype vchPushValue;
    while (spt.GetOp(it, opcode, vchPushValue)) {
        if (vchPushValue.size() > 0) {
            for (auto& path : paths) {
                if (path.is_active()) {
                    path.touch(1, 0);
                    path.script << vchPushValue;
                }
            }
        } else {
            interpret_opcode(paths, opcode);
        }
    }

    // if arguments were provided, execute the original script and determine which path was selected
    current_path = 0;
    selected_path = args.size() > 0;
    if (args.size()) {
        btc_logf = btc_logf_dummy;
        std::vector<valtype> stack;
        BaseSignatureChecker checker;
        ScriptError error;
        for (auto p : args) {
            stack.push_back(p.data_value());
        }
        auto env = new InterpreterEnv(stack, spt, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_TAPROOT, checker, SigVersion::TAPROOT /* TAPSCRIPT? */, &error);
        while (!env->done) {
            // iterate
            if (!StepScript(*env)) {
                fprintf(stderr, "error: script failure: %s\n", ScriptErrorString(error));
                return -1;
            }
            // update path
            update_path(current_path, paths, env->opcode, env->vfExec);
        }
        btc_logf("resulting path: %zu\n", current_path);
        delete env;
    }

    for (auto& path : paths) path.add_fromaltstacks();

    if (!selected_path) {
        printf("%zu paths:\n", paths.size());
        for (size_t i = 0; i < paths.size(); i++) {
            printf("path #%zu (%zu arguments):\n", i, paths[i].params);
            CScript spt = paths[i].script;
            CScript::const_iterator it = spt.begin();
            opcodetype opcode;
            valtype vchPushValue;
            while (spt.GetOp(it, opcode, vchPushValue)) {
                if (vchPushValue.size() > 0) {
                    printf("%s\n", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
                } else {
                    printf("%s\n", GetOpName(opcode));
                }
            }
            printf("\n");
        }
    }

    std::vector<Value> leaves;
    for (size_t i = 0; i < paths.size(); i++) {
        leaves.emplace_back(paths[i].script);
    }

    std::vector<uint256> hashes;
    for (size_t i = 0; i < leaves.size(); ++i) {
        uint256 hash;
        const std::vector<unsigned char> leaf = leaves[i].data_value();
        CHash256().Write(&leaf[0], leaf.size()).Finalize(hash.begin());
        hashes.push_back(hash);
    }
    // if (!piping) {
    //     printf("leaves: [\n");
    //     for (size_t i = 0; i < hashes.size(); ++i) {
    //         printf("\t%s\n", HexStr(hashes[i]).c_str());
    //     }
    //     printf("]\n");
    // }
    size_t cap = selected_path ? current_path + 1 : leaves.size();
    for (int pos = selected_path ? current_path : 0; pos < cap; pos++) {
        uint256 root;
        std::vector<uint256> branch;
        uint32_t path;
        std::vector<unsigned char> proof;

        if (!selected_path) printf("path #%d proposal:\n", pos);
        size_t params = paths[pos].params;
        if (!fast) {
            fprintf(stderr, "error: legacy mode not supported (yet)\n");
            return -1;
            // branch = ComputeMerkleBranch(hashes, pos);
            // root = ComputeMerkleRootFromBranch(hashes[pos], branch, pos);
            // path = (uint32_t)pos;
            // // proof is clear
        } else {
            std::pair<std::vector<uint256>, uint32_t> r = ComputeFastMerkleBranch(hashes, pos);
            root = ComputeFastMerkleRootFromBranch(hashes[pos], r.first, r.second);
            btc_logf("root: %s\n", HexStr(root).c_str());
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

        if (!piping) {
            printf("branch: [\n");
            for (auto h = branch.begin(); h != branch.end(); ++h) {
                printf("\t%s\n", HexStr(*h).c_str());
            }
            printf("]\n");
            printf("path: %d\n", path);
        } else if (proof.empty()) {
            fprintf(stderr, "empty proof\n");
            return -1;
        }
        // if (!proof.empty()) {
        //     if (!piping) {
        //         printf("proof: %s\n", HexStr(proof).c_str());
        //         printf("unlocking script: %s %s OP_%d OP_MERKLEBRANCHVERIFY 2DROP DROP\n", repeat("TOALTSTACK", params).c_str(), HexStr(root).c_str(), 2 + preprocessed);
        //     }
        //     if (!piping || btcdeb) {
        //         printf(piping
        //             ? "%s20%s5%db36d75\n"
        //             : "- script (hex): %s20%s5%db36d75\n",
        //             repeat("6b", params, "").c_str(),
        //             HexStr(root).c_str(),
        //             2 + preprocessed
        //         );
        //         btc_logf("stack:\n");
        //     }
        //     printf(piping ? "%s\n" : "- item #1:  %s\n", leaves[pos].hex_str().c_str());
        //     printf(piping ? "%s\n" : "- item #2:  %s\n", HexStr(proof).c_str());
        //     for (auto& arg : args) printf(piping ? "0x%s\n" : "- argument: 0x%s\n", arg.hex_str().c_str());
        // }
    }
}
