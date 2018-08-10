
#include <tinycv.h>
#include <instance.h>
#include <script/script.h>

std::string rpc_call = "";

std::vector<std::string> fetched_purgable;

void push_purgable(const char* path) {
    fetched_purgable.emplace_back(path);
    while (fetched_purgable.size() > 100000) {
        std::string s = fetched_purgable[0];
        fprintf(stderr, "unlinking %s\n", s.c_str());
        fetched_purgable.erase(fetched_purgable.begin());
        unlink(s.c_str());
    }
}

inline FILE* rpc_fetch(const char* cmd, const char* dst, bool abort_on_failure = false) {
    if (rpc_call == "") {
        assert(!"no RPC call available");
    }
    system(cmd);
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
        system(cmd.c_str());
        fphdr = fopen(dstheight.c_str(), "r");
        assert(1 == fscanf(fphdr, "%u", &height));
        fclose(fphdr);                                      // closes fphdr (.height open)
        fseek(fphex, 0, SEEK_END);
        size_t sz = ftell(fphex);
        fseek(fphex, 0, SEEK_SET);
        char* blk = (char*)malloc(sz + 1);
        assert(blk);
        fread(blk, 1, sz, fphex);
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
    fread(&height, sizeof(uint32_t), 1, fp);
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
        fscanf(fptxt, "%s", hex);
        assert(strlen(hex) == 64);
        blockhex = uint256S(hex);
        fclose(fptxt);
        fp = fopen(dstfinal.c_str(), "wb");
        CAutoFile af(fp, SER_DISK, 0);
        af << blockhex;
        return rpc_get_block(blockhex, b, height);
    }
    CAutoFile af(fp, SER_DISK, 0);
    af >> blockhex;
    return rpc_get_block(blockhex, b, height);
}

bool CastToBool(const valtype& vch);

unsigned int get_flags(int height) {
    unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (height < 163686) flags ^= SCRIPT_VERIFY_LOW_S;
    return flags;
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
    tiny::block b;
    uint256 blockhex;

    // see if we have a state we can read in from
    FILE* fp = fopen("current-sync-state.dat", "rb");
    if (fp) {
        printf("restoring from state..."); fflush(stdout);
        CAutoFile af(fp, SER_DISK, 0);
        af >> height >> view;
        printf("\n");
    }

    for (;;) {
        ++height;
        printf("block #%d", height); fflush(stdout);
        rpc_get_block(height, b, blockhex);
        printf("=%s (#tx = %zu)\n", blockhex.ToString().c_str(), b.vtx.size());
        
        // process each input of each transaction, except coinbases
        size_t idx = 0;
        for (auto& x : b.vtx) {
            printf("tx #%zu=%s: ", idx, x.hash.ToString().c_str()); fflush(stdout);
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

                    if (!instance.setup_environment(get_flags(height))) {
                        fprintf(stderr, "block %s, index %zu tx %s failed to initialize script environment for input %d=%s: %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), instance.error_string());
                        exit(1);
                    }

                    auto& env = instance.env;

                    if (!ContinueScript(*env)) {
                        fprintf(stderr, "error: %s\n", ScriptErrorString(*env->serror));
                        return 1;
                    }

                    // stack should have 1 item. it should be true
                    if (env->stack.size() != 1) {
                        fprintf(stderr, "block %s, index %zu tx %s finished execution with non-1 stack size for input %d=%s: size() == %zu\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), env->stack.size());
                        return 1;
                    }
                    if (!CastToBool(env->stack[0])) {
                        fprintf(stderr, "block %s, index %zu tx %s finished execution with non-truthy on stack for input %d=%s: stack top = %s\n", blockhex.ToString().c_str(), idx, x.hash.ToString().c_str(), selected, vin.prevout.hash.ToString().c_str(), HexStr(env->stack[0]).c_str());
                        return 1;
                    }

                    printf("."); fflush(stdout);
                }
            }
            view.insert(ptx);
            idx++;
            printf("\n");
        }

        if ((height % 100) == 0) {
            // save view and height to disk
            printf("writing state to disk..."); fflush(stdout);
            {
                FILE* fp = fopen("current-sync-state.dat", "wb");
                CAutoFile af(fp, SER_DISK, 0);
                af << height << view;
            }
            printf("\n");
        }
    }
}
