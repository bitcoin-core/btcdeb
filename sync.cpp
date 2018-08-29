
#include <tinycv.h>
#include <instance.h>
#include <script/script.h>

int tiny::coin_view_version = 2;

std::string rpc_call = "";

std::vector<std::string> fetched_purgable;

void push_purgable(const char* path) {
    fetched_purgable.emplace_back(path);
    while (fetched_purgable.size() > 100) {
        std::string s = fetched_purgable[0];
        fetched_purgable.erase(fetched_purgable.begin());
        unlink(s.c_str());
    }
}

inline FILE* rpc_fetch(const char* cmd, const char* dst, bool abort_on_failure = false) {
    if (rpc_call == "") {
        assert(!"no RPC call available");
    }
    if (system(cmd)) { fprintf(stderr, "failed to run command: %s\n", cmd); exit(1); }
    FILE* fp = fopen(dst, "r");
    if (!fp) {
        fprintf(stderr, "RPC call failed: %s\n", cmd);
        if (!abort_on_failure) {
            fprintf(stderr, "waiting 5 seconds and trying again\n");
            sleep(5);
            return rpc_fetch(cmd, dst, true);
        }
        assert(0);
    }
    push_purgable(dst);
    return fp;
}

template<typename T>
inline void deserialize_hex_string(const char* string, T& object) {
    CDataStream ds(ParseHex(string), SER_DISK, 0);
    ds >> object;
}

template<typename T>
inline void serialize_object(const T& object, std::vector<uint8_t>& bin) {
    CVectorWriter ds(SER_DISK, 0, bin, 0);
    ds << object;
}

void rpc_get_block(const uint256& blockhex, tiny::block& b, uint32_t& height) {
    // printf("get block %s\n", blockhex.ToString().c_str());
    std::string dstfinal = "blockdata/" + blockhex.ToString() + ".mffb";
    FILE* fp = fopen(dstfinal.c_str(), "rb");
    if (!fp) {
        std::string dsthex = "blockdata/" + blockhex.ToString() + ".hex";
        std::string dsthdr = "blockdata/" + blockhex.ToString() + ".hdr";
        FILE* fphex = fopen(dsthex.c_str(), "r");
        FILE* fphdr = fopen(dsthdr.c_str(), "r");
        if (!fphex) {
            std::string cmd = rpc_call + " getblock " + blockhex.ToString() + " 0 > " + dsthex;
            fphex = rpc_fetch(cmd.c_str(), dsthex.c_str());
        }
        if (!fphdr) {
            std::string cmd = rpc_call + " getblockheader " + blockhex.ToString() + " > " + dsthdr;
            fphdr = rpc_fetch(cmd.c_str(), dsthdr.c_str());
        }
        fclose(fphdr);                                      // closes fphdr
        std::string dstheight = std::string("blockdata/") + blockhex.ToString() + ".height";
        std::string cmd = std::string("cat ") + dsthdr + " | jq -r .height > " + dstheight;
        if (system(cmd.c_str())) { fprintf(stderr, "failed to run command: %s\n", cmd.c_str()); exit(1); }
        fphdr = fopen(dstheight.c_str(), "r");
        assert(1 == fscanf(fphdr, "%u", &height));
        fclose(fphdr);                                      // closes fphdr (.height open)
        fseek(fphex, 0, SEEK_END);
        size_t sz = ftell(fphex);
        fseek(fphex, 0, SEEK_SET);
        char* blk = (char*)malloc(sz + 1);
        assert(blk);
        if (sz != fread(blk, 1, sz, fphex)) { fprintf(stderr, "unable to read from input file %s\n", dsthex.c_str()); exit(1); }
        fclose(fphex);                                      // closes fphex
        blk[sz] = 0;
        std::vector<uint8_t> blkdata = ParseHex(blk);
        free(blk);
        fp = fopen(dstfinal.c_str(), "wb+");
        // write height
        fwrite(&height, sizeof(uint32_t), 1, fp);
        // write block
        fwrite(blkdata.data(), 1, blkdata.size(), fp);
        fseek(fp, 0, SEEK_SET);
        // unlink
        unlink(dsthex.c_str());
        unlink(dsthdr.c_str());
        unlink(dstheight.c_str());
    }
    // read height
    if (1 != fread(&height, sizeof(uint32_t), 1, fp)) {
        fprintf(stderr, "unable to read from input file %s\n", dstfinal.c_str());
    }
    // deserialize block
    CAutoFile deserializer(fp, SER_DISK, 0);
    deserializer >> b;
    // deserializer closes fp
}

void rpc_get_block(uint32_t height, tiny::block& b, uint256& blockhex) {
    std::string dstfinal = "blockdata/" + std::to_string(height) + ".hth";
    FILE* fp = fopen(dstfinal.c_str(), "rb");
    if (!fp) {
        std::string dsttxt = "blockdata/" + std::to_string(height) + ".hth.txt";
        FILE* fptxt = fopen(dsttxt.c_str(), "r");
        if (!fptxt) {
            std::string cmd = rpc_call + " getblockhash " + std::to_string(height) + " > " + dsttxt;
            fptxt = rpc_fetch(cmd.c_str(), dsttxt.c_str());
        }
        char hex[128];
        if (1 != fscanf(fptxt, "%s", hex)) { fprintf(stderr, "unable to scan from input file %s\n", dsttxt.c_str()); exit(1); }
        assert(strlen(hex) == 64);
        blockhex = uint256S(hex);
        fclose(fptxt);
        fp = fopen(dstfinal.c_str(), "wb");
        CAutoFile af(fp, SER_DISK, 0);
        af << blockhex;
        push_purgable(dstfinal.c_str());
        return rpc_get_block(blockhex, b, height);
    }
    CAutoFile af(fp, SER_DISK, 0);
    af >> blockhex;
    return rpc_get_block(blockhex, b, height);
}

int print_stack(std::vector<valtype>& stack, bool raw) {
    if (raw) {
        for (auto& it : stack) printf("%s\n", HexStr(it.begin(), it.end()).c_str());
    } else {
        if (stack.size() == 0) printf("- empty stack -\n");
        int i = 0;
        for (int j = stack.size() - 1; j >= 0; j--) {
            auto& it = stack[j];
            i++;
            printf("<%02d>\t%s%s\n", i, HexStr(it.begin(), it.end()).c_str(), i == 1 ? "\t(top)" : "");
        }
    }
    return 0;
}

bool CastToBool(const valtype& vch);

// From chainparams.cpp:
static const auto BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
#define BIP34Height 227931
#define BIP34Hash   uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8")
#define BIP65Height 388381 // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
#define BIP66Height 363725 // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931

// Exceptions
static const auto MinimalDataExceptTX = std::set<uint256>{
    uint256S("0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae"),
    uint256S("7caed7650c392c24e44a093f30438fe6dc9ec1154b92bedc8a561130c9c50920"),
    uint256S("cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2"),
    uint256S("567a53d1ce19ce3d07711885168484439965501536d0d0294c5d46d46c10e53b"),
    uint256S("59ac3eccee265d31bee3264cf77a4e9b7703d6ad0cf97eadcdb4439c22725db2"),
    uint256S("ad1209c76f94e2eb80b9929021161adce12498ce919333e50fa1fd4e5f6dead2"),
    uint256S("e57364803169c23c245a643301097682036be61918eee362334d9d710c74dbd4"),
    uint256S("a9b61a5aa4e406b0c9fb5ed9007bd87b6273117f502fa9e100ec08fb347d08db"),
    uint256S("059787f0673ab2c00b8f2f9810fdd14b0cd6a3034cc44dc30de124f606d3670a"),
    uint256S("dca2b033741d59a5c07e42adf04d36707aceae76596d883827fbd6e9ffa6d909"),
    uint256S("f10f94e9305abf3dc90f1c3e965574a208c92a7fd71f6fb8f948abb455bba506"),
    uint256S("87ef8c3ce56e1cb99a1be9c70fea6645d5e3668eab081857d8ccee09d1802c12"),
    uint256S("158c4311575a869cda8c965c64f702571182083a68d21876ca19c499cf58031f"),
    uint256S("5d6947307cf6d0be19078c2995542814f6cd2cf63e39a78789471bc034ad5e38"),
    uint256S("99898f1e9835d12216deeadf9a83394e460863dfb597351a61266a69829df56e"),
    uint256S("dadfc42bc0e0c0d8b00a9d574adb0bb623bc7195a84a37b9823e8638782517af"),
    uint256S("2a56b65eea3e60d5df2347fae1c82ce49a70e143ce392a1e46838c57f051b3b5"),
    uint256S("09bdfd8bd713658612594e2d6df5e7f80ba3898e3ae3c6b3aa8ef986204d1e1e"),
};
static const auto DummyMultisigExceptTX = std::set<uint256>{
    uint256S("825baed503ce5d28bf7332b6dac4751aaceea5cf2df9148b90cbc61894b65261"),
    uint256S("320a5c8eb5e8e0d4fc2ae48fc6f2d1c86ebe637193a61fcc9a13925d9cf96b1b"),
    uint256S("8e8b01b99048ee68bfe378dd7eb7fc8c1d5b1864aa74a76f4dc97ed38fbfe15e"),
    uint256S("15bb08318335f94a8de154dc39b03db2cdebcc7a96ab6cec0379978676d00301"),
    uint256S("f0ac94fc28d011b6145a69d0790e30669bb9148b2bd02a9e11a728d75ad2bb08"),
    uint256S("cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2"),
    uint256S("b16bf8cfca4c2bfaa250c378e4f73662c1ef99a1794a127d4d57321ddd73d367"),
    uint256S("61e26d407c17e8ee33a8b166c78f78c53cdcdc0078ae1f9405e6583cfb90eaf4"),
    uint256S("e60547f1fea31e2104301cfac210402205151fb09816ede05858806662416bd8"),
    uint256S("fd9b541d23f6e9bddb34ede15c7684eeec36231118796b691ae525f95578acf1"),
    uint256S("38df010716e13254fb5fc16065c1cf62ee2aeaed2fad79973f8a76ba91da36da"),
};
static const auto NullFailExceptTX = std::set<uint256>{
    uint256S("be774942fc7f8ed3e89ec8c750e6b4f52983b758f869e7249dad0c3f7d57a294"),
    uint256S("fd9b541d23f6e9bddb34ede15c7684eeec36231118796b691ae525f95578acf1"),
};
static const auto UpgradableNOPExceptTX = std::set<uint256>{
    uint256S("c8b86e0dcfe3a1dd48c99ee4b5ddf6172a552303e7f338d49124e060caf62d09"),
};
std::set<uint256> mindata;
std::set<uint256> nullfail;
std::set<uint256> nulldummy;
std::set<uint256> upgradablenop;
std::set<uint256> lows;
std::set<uint256> strictencs;
#define UpgradableNops 212615 // last offender 212614, tx 03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99

// Deployment of BIP68, BIP112, and BIP113.
#define CSVHeight 419328
// Segwit
#define SWHeight  481824

unsigned int get_flags(int height, const uint256& blockhash, const uint256& txid) {
    unsigned int dflags = 0;
    if (height < BIP66Height) dflags |= SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S;
    if (height < BIP65Height) dflags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    if (height < CSVHeight) dflags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    if (height < SWHeight) dflags |= SCRIPT_VERIFY_WITNESS;
    if (height < UpgradableNops || upgradablenop.count(txid)) dflags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    if (blockhash == BIP16Exception) dflags |= SCRIPT_VERIFY_P2SH;
    if (mindata.count(txid)) dflags |= SCRIPT_VERIFY_MINIMALDATA;
    if (nulldummy.count(txid)) dflags |= SCRIPT_VERIFY_NULLDUMMY;
    if (nullfail.count(txid)) dflags |= SCRIPT_VERIFY_NULLFAIL;
    if (lows.count(txid)) dflags |= SCRIPT_VERIFY_LOW_S;
    if (strictencs.count(txid)) dflags |= SCRIPT_VERIFY_STRICTENC;
    return STANDARD_SCRIPT_VERIFY_FLAGS & ~dflags;
}

inline void mark(const uint256& hash, std::set<uint256>& set, const std::string& fprefix) {
    set.insert(hash);
    FILE* fp = fopen((fprefix + ".txt").c_str(), "a+");
    if (!fp) fp = fopen((fprefix + ".txt").c_str(), "w");
    fprintf(fp, "%s\n", hash.ToString().c_str());
    fclose(fp);
    printf("%s: +%s\n", fprefix.c_str(), hash.ToString().c_str());
}

inline void load_e(std::set<uint256>& set, const std::string& fprefix) {
    FILE* fp = fopen((fprefix + ".txt").c_str(), "r");
    if (!fp) return;
    char buf[70];
    while (nullptr != (fgets(buf, 70, fp))) {
        assert(strlen(buf) == 65); // 64 byte hex + '\n'
        buf[64] = 0; // chop off newline
        set.insert(uint256S(buf));
    }
    fclose(fp);
}

int main(int argc, const char** argv)
{
    if (argc == 0) {
        fprintf(stderr, "syntax: %s \"bitcoin RPC call string\"\n", argv[0]);
        return 1;
    }
    rpc_call = argv[1];
    printf("rpc call: %s\n", argv[1]);

    btc_logf = btc_logf_dummy;

    tiny::view view;
    int height = 0;
    uint64_t txs = 0;
    tiny::block b;
    uint256 blockhex;

    // see if we have a state we can read in from
    FILE* fp = fopen("current-sync-state.dat", "rb");
    if (fp) {
        printf("restoring from state..."); fflush(stdout);
        CAutoFile af(fp, SER_DISK, 0);
        af >> height >> view >> txs;
        printf("\n");
    }

    // load exceptions
    mindata = MinimalDataExceptTX;
    nullfail = NullFailExceptTX;
    nulldummy = DummyMultisigExceptTX;
    upgradablenop = UpgradableNOPExceptTX;

    fp = fopen("exceptions.dat", "rb");
    if (fp) {
        CAutoFile af(fp, SER_DISK, 0);
        af >> mindata >> nullfail >> nulldummy >> upgradablenop;
        try {
            af >> lows;
            af >> strictencs;
        } catch (...) {}
        printf("loaded [ %zu, %zu, %zu, %zu, %zu, %zu ] exceptions\n", mindata.size(), nullfail.size(), nulldummy.size(), upgradablenop.size(), lows.size(), strictencs.size());
    }

    // below is no longer needed, as the data is duplicated in the exceptions.dat file
    // // append exceptions
    // load_e(mindata, "mindata");
    // load_e(nullfail, "nullfail");
    // load_e(nulldummy, "nulldummy");
    // load_e(upgradablenop, "upgradablenop");
    // load_e(lows, "lows");
    // load_e(strictencs, "strictencs");

    ECCVerifyHandle evh;
    for (;;) {
        ++height;
        txs += b.vtx.size();
        printf("block #%d", height); fflush(stdout);
        rpc_get_block(height, b, blockhex);
        printf("=%s (#tx = %4zu; total = %9llu)\n", blockhex.ToString().c_str(), b.vtx.size(), (unsigned long long)txs);
        
        // process each input of each transaction, except coinbases
        size_t idx = 0;
        for (auto& x : b.vtx) {
            // printf("tx #%zu=%s: ", idx, x.hash.ToString().c_str()); fflush(stdout);
            std::shared_ptr<tiny::tx> ptx = std::make_shared<tiny::tx>(x);
            if (!x.IsCoinBase()) {
                std::string tx_str;
                {
                    std::vector<uint8_t> b;
                    serialize_object(x, b);
                    tx_str = HexStr(b);
                }
                for (int selected = 0; selected < x.vin.size(); ++selected) {
                    auto& vin = x.vin[selected];
                    Instance instance;
                    if (!instance.parse_transaction(tx_str.c_str(), true)) {
                        fprintf(stderr, "block %s, index %zu failed to parse tx %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str());
                        exit(1);
                    }
                    auto txin = view.get(vin.prevout.hash);
                    if (!txin) {
                        fprintf(stderr, "block %s, index %zu tx %s could not find input tx %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), vin.prevout.hash.ToString().c_str());
                        exit(1);
                    }
                    {
                        std::vector<uint8_t> b;
                        serialize_object(*txin, b);
                        if (!instance.parse_input_transaction(HexStr(b).c_str(), selected)) {
                            fprintf(stderr, "block %s, index %zu tx %s failed to parse input tx %d=%s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str());
                            exit(1);
                        }
                    }

                    if (!instance.configure_tx_txin()) {
                        fprintf(stderr, "block %s, index %zu tx %s failed to configure tx/txin for input %d=%s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str());
                        exit(1);
                    }
                    bool require_cleanstack = instance.sigver == SigVersion::WITNESS_V0;

                    if (!instance.setup_environment(get_flags(height, blockhex, x.hash))) {
                        fprintf(stderr, "block %s, index %zu tx %s failed to initialize script environment for input %d=%s: %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), instance.error_string().c_str());
                        exit(1);
                    }

                    auto& env = instance.env;

                    bool result = false;
                    try {
                        result = ContinueScript(*env);
                    } catch (scriptnum_error const& ex) {
                        fprintf(stderr, "block %s, index %zu tx %s raised a scriptnum error on validating input %d=%s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str());
                        if (mindata.count(x.hash)) {
                            fprintf(stderr, "error: %s (mindata inclusion did not fix)\n", ex.what());
                            exit(1);
                        }
                        mark(x.hash, mindata, "mindata");
                        selected--;
                        continue;
                    } catch (std::exception const& ex) {
                        fprintf(stderr, "block %s, index %zu tx %s raised an exception on validating input %d=%s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str());
                        fprintf(stderr, "error: %s\n", ex.what());
                        exit(1);
                    }

                    if (!result) {
                        if (*env->serror == SCRIPT_ERR_SIG_HIGH_S) {
                            mark(x.hash, lows, "lows");
                            selected--;
                            continue;
                        }
                        fprintf(stderr, "block %s, index %zu tx %s failed to validate input %d=%s: %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), instance.error_string().c_str());
                        fprintf(stderr, "error: %s\n", ScriptErrorString(*env->serror));
                        if (*env->serror == SCRIPT_ERR_MINIMALDATA) {
                            mark(x.hash, mindata, "mindata");
                            selected--;
                            continue;
                        }
                        if (*env->serror == SCRIPT_ERR_SIG_NULLFAIL) {
                            mark(x.hash, nullfail, "nullfail");
                            selected--;
                            continue;
                        }
                        if (*env->serror == SCRIPT_ERR_SIG_NULLDUMMY) {
                            mark(x.hash, nulldummy, "nulldummy");
                            selected--;
                            continue;
                        }
                        if (*env->serror == SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) {
                            mark(x.hash, upgradablenop, "upgradablenop");
                            selected--;
                            continue;
                        }
                        if (*env->serror == SCRIPT_ERR_PUBKEYTYPE) {
                            mark(x.hash, strictencs, "strictencs");
                            selected--;
                            continue;
                        }
                        return 1;
                    }

                    // stack should have 1 item. it should be true
                    if (env->stack.size() != 1) {
                        fprintf(stderr, "block %s, index %zu tx %s finished execution with non-1 stack size for input %d=%s: size() == %zu\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), env->stack.size());
                        if (require_cleanstack) return 1;
                    }
                    if (!CastToBool(env->stack.back())) {
                        fprintf(stderr, "block %s, index %zu tx %s finished execution with non-truthy on stack for input %d=%s: stack top = %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), HexStr(env->stack[0]).c_str());
                        print_stack(env->stack, false);
                        return 1;
                    }

                    // printf("."); fflush(stdout);
                }
            }
            view.insert(ptx);
            idx++;
            // printf("\n");
        }

        if ((height % 100) == 0) {
            // save view and height to disk
            printf("writing state to disk..."); fflush(stdout);
            {
                FILE* fp = fopen("current-sync-state.new", "wb");
                CAutoFile af(fp, SER_DISK, 0);
                af << height << view << txs;
            }
            // {
            //     tiny::view view2;
            //     FILE* fp = fopen("current-sync-state.new", "rb");
            //     if (fp) {
            //         CAutoFile af(fp, SER_DISK, 0);
            //         af >> height >> view2 >> txs;
            //     }
            //     assert(view == view2);
            //     // FILE* fp2 = fopen("tmpfile", "wb");
            //     // if (fp2) {
            //     //     CAutoFile af(fp2, SER_DISK, 0);
            //     //     af << height << view2 << txs;
            //     // }
            // }
            // {
            //     FILE* fp = fopen("current-sync-state.new", "rb");
            //     FILE* fp2 = fopen("tmpfile", "rb");
            //     char* buf = (char*)malloc(65536);
            //     char* buf2 = (char*)malloc(65536);
            //     size_t z, z2;
            //     while (0 != (z = fread(buf, 1, 65536, fp))) {
            //         z2 = fread(buf2, 1, 65536, fp2);
            //         if (z != z2) {
            //             printf("file sizes differ: read %zu vs %zu b\n", z, z2);
            //             exit(99);
            //         }
            //         if (memcmp(buf, buf2, z)) {
            //             printf("files differ around byte %ld\n", ftell(fp) - z);
            //             exit(99);
            //         }
            //     }
            //     fclose(fp);
            //     fclose(fp2);
            //     free(buf);
            //     free(buf2);
            // }
            unlink("current-sync-state.dat");
            rename("current-sync-state.new", "current-sync-state.dat");
            printf("\n");
            {
                fp = fopen("exceptions.dat", "wb");
                CAutoFile af(fp, SER_DISK, 0);
                af << mindata << nullfail << nulldummy << upgradablenop << lows << strictencs;
            }
            static int milestones[] = {1000, 5000, 10000};
            bool update[] = {false, false, false};
            bool do_update = false;
            for (int m = 0; m < 3; ++m) {
                do_update |= (update[m] = (height % milestones[m]) == 0);
            }
            if (do_update) {
                fp = fopen("current-sync-state.dat", "rb");
                FILE* fp2[3];
                std::string fname[3];
                printf("backing up ");
                int j = 0;
                for (int m = 0; m < 3; ++m) if (update[m]) {
                    printf("%dk ", milestones[m]/1000);
                    fname[j] = strprintf("backup-state-%dk.dat", milestones[m]/1000);
                    fp2[j] = fopen(fname[j].c_str(), "wb");
                    j++;
                }
                printf("block state%s...", j == 1 ? "" : "s");
                fflush(stdout);

                char* buf = (char*)malloc(65536);
                size_t sz;
                while (0 < (sz = fread(buf, 1, 65536, fp))) {
                    for (int m = 0; m < j; ++m) {
                        if (sz != fwrite(buf, 1, sz, fp2[m])) {
                            fprintf(stderr, "error: could not write to file %s; disk full?\n", fname[m].c_str());
                            return 1;
                        }
                    }
                }
                fclose(fp);
                for (int m = 0; m < j; ++m) fclose(fp2[m]);
                // {
                //     tiny::view view2;
                //     FILE* fp = fopen("backup-state-1k.dat", "rb");
                //     if (fp) {
                //         CAutoFile af(fp, SER_DISK, 0);
                //         af >> height >> view2 >> txs;
                //     }
                //     assert(view == view2);
                // }
                printf("\n");
            }
        }
    }
}
