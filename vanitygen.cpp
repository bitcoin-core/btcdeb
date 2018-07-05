#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

#include <cstdio>
#include <unistd.h>

#include <utilstrencodings.h>
#include <tinyformat.h>
#include <value.h>

#include <cliargs.h>

#include <secp256k1.h>

#include <support/allocators/secure.h>

#include <ansi-colors.h>

bool quiet = false;

/** The Bech32 character set for encoding. */
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** The Bech32 character set for decoding. */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

void decode_bech32_prefix(const char* prefix, std::vector<uint8_t>& result, uint8_t& final_mask) {
    size_t len = strlen(prefix);
    int8_t fivebitvals[len];
    for (size_t i = 0; prefix[i]; ++i) {
        fivebitvals[i] = CHARSET_REV[prefix[i]];
        if (fivebitvals[i] == -1) printf("CHARACTER %c IS %d IN CHARSET_REV !!!\n", prefix[i], CHARSET_REV[prefix[i]]);
        assert(-1 < fivebitvals[i]);
    }
    if (!ConvertBits<5, 8, true>(result, fivebitvals, fivebitvals + len)) {
        assert(!"failed ConvertBits call");
    }
    // 5 bit        3
    // 10 bit       6
    // 15           1
    // 8 - (5 % 8) = 8 - 5 = 3
    // 8 - (10 % 8) = 8 - 2 = 6
    // 8 - (15 % 8) = 8 - 7 = 1
    final_mask = 0xff << (8 - ((5 * len) & 0x07));
}

#define KP_CHUNK_SIZE 1024
#define SHOW_ALTS_AT  7     // start showing alternatives at this many matching letters

struct probability {
    size_t letters, bits;
    probability(size_t letters_in, size_t bits_in) : letters(letters_in), bits(bits_in) {}
    std::string one_in_string() const {
        static const char* v = "kMGTPE";
        size_t unit = (letters * bits) / 10;
        if (unit < 1) return std::to_string(1ULL << (letters * bits));
        if (unit > 6) unit = 6;
        size_t remainder = (letters * bits) - unit * 10;
        return std::to_string(1ULL << remainder) + v[unit-1];
    }
    std::string percentage() const {
        std::string s = "0.";
        double d = 100.0;
        size_t div = 1 << bits;
        for (size_t i = 0; i < letters; i++) d /= div;
        assert(d < 1.0);
        while (d < 1.0) {
            s += "0";
            d *= 10;
        }
        d *= 10;
        s += std::to_string(int(d));
        return s;
    }
    double expected_time(double combinations_per_sec) const {
        // we want (1 << (letters * bits)) / combinations_per_sec
        size_t shifts = letters * bits;
        while (shifts > 60 && combinations_per_sec > 1024) {
            shifts -= 10;
            combinations_per_sec /= 1024;
        }
        while (shifts > 60 && combinations_per_sec > 2) {
            shifts--;
            combinations_per_sec /= 2;
        }
        if (shifts > 60) {
            double v = 1.0;
            for (size_t i = 0; i < shifts; i++) v *= 2;
            return v / combinations_per_sec;
        }
        return double(1ULL << shifts) / combinations_per_sec;
    }
};

typedef std::chrono::milliseconds milliseconds;

inline milliseconds time_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch());
}

inline bool in(char c, const char* v, size_t l) {
    for (size_t i = 0; i < l; ++i) if (v[i] == c) return true;
    return false;
}

void ansi_print_compare(const char* show, const char* compare, size_t offset) {
    bool matching = false;
    size_t i;
    for (i = 0; show[i] && i < offset; ++i) putchar(show[i]);
    std::string wrong = ansi::fg_red + ansi::bold;
    std::string right = ansi::fg_green + ansi::bold;
    printf("%s", wrong.c_str());
    for (; show[i] && compare[i-offset]; ++i) {
        if ((compare[i-offset] == '?' || show[i] == compare[i-offset]) && !matching) {
            printf("%s", right.c_str());
            matching = true;
        } else if (compare[i-offset] != '?' && show[i] != compare[i-offset] && matching) {
            printf("%s", wrong.c_str());
            matching = false;
        }
        putchar(show[i]);
    }
    printf("%s", ansi::reset.c_str());
    printf("%s", &show[i]);
}

struct privkey_store {
    const char* prefix;
    milliseconds start_time;
    std::vector<std::vector<uint8_t>> v;
    std::mutex mtx;
    size_t longest_match = 3;
    probability& prob;
    size_t cap = 0;
    bool complete_match = false;
    bool end = false;
    FILE* fp = nullptr;
    std::atomic<size_t> counter;

    privkey_store(probability& prob_in) : prob(prob_in) {
        fp = fopen("/dev/urandom", "rb");
        assert(fp && "/dev/urandom required");
        start_time = time_ms();
    }

    inline void new_match(const char* str, const uint8_t* u, size_t longest, bool complete) {
        std::lock_guard<std::mutex> guard(mtx);
        if (!(longest > longest_match || (longest > SHOW_ALTS_AT && longest == longest_match))) return;
        if (longest_match == longest) {
            printf("\n* alternative match: ");
            ansi_print_compare(str, prefix, 4);
            printf("\n* privkey:           %s\n", HexStr(u, u + 32).c_str());
            return;
        }
        longest_match = longest;
        complete_match = complete;
        printf("\n* new %s match: ", complete ? "full" : "longest");
        ansi_print_compare(str, prefix, 4);
        printf("\n* privkey:%s        %s\n", complete ? "" :     "   ", HexStr(u, u + 32).c_str());
    }
};

std::string timestr(unsigned long seconds) {
    unsigned long minutes = seconds / 60;
    seconds %= 60;
    unsigned long hours = minutes / 60;
    minutes %= 60;
    unsigned long days = hours / 24;
    hours %= 24;
    unsigned long qdays = days << 2;
    unsigned long years = qdays / 1461;
    qdays %= 1461;
    days = qdays >> 2;
    std::string s = "";
    if (years > 0) s += strprintf("%lu year%s", years, years == 1 ? "" : "s");
    if (days > 0) s += strprintf("%s%lu day%s", years ? ", " : "", days, days == 1 ? "" : "s");
    if (years == 0 && hours > 0) s += strprintf("%s%lu hour%s", days ? ", " : "", hours, hours == 1 ? "" : "s");
    if (minutes > 0 && years + days == 0) s += strprintf("%s%lu min%s", hours ? ", " : "", minutes, minutes == 1 ? "" : "s");
    if (seconds > 0 && years + days + hours == 0) s += strprintf("%s%lu second%s", minutes ? ", " : "", seconds, seconds == 1 ? "" : "s");
    return s;
}

std::string shorttimestr(unsigned long seconds) {
    unsigned long minutes = seconds / 60;
    seconds %= 60;
    unsigned long hours = minutes / 60;
    minutes %= 60;
    unsigned long days = hours / 24;
    hours %= 24;
    unsigned long qdays = days << 2;
    unsigned long years = qdays / 1461;
    qdays %= 1461;
    days = qdays >> 2;
    std::string s = "";
    if (years > 0) s += strprintf(" %luY", years);
    if (years + days > 0) s += strprintf(" %luD", days);
    s += strprintf(" %02lu:%02lu.%02lu", hours, minutes, seconds);
    return s.substr(1);
}

#define xprintf(args...) printf("%s ", shorttimestr(std::chrono::duration<double>(time_ms() - store->start_time).count()).c_str()); printf(args)

void finder(size_t id, int step, const char* prefix, std::vector<uint8_t> coded, uint8_t final_mask, privkey_store* store) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        void GetRandBytes(unsigned char* buf, int num);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    size_t plen = strlen(prefix);
    secp256k1_pubkey* pubs = new secp256k1_pubkey[KP_CHUNK_SIZE];
    unsigned char* privs = new unsigned char[32 * KP_CHUNK_SIZE];
    size_t iter = KP_CHUNK_SIZE;
    size_t local_ctr = 0;
    size_t next_eta = 1000000000;
    size_t start = 0;
    while (prefix[start] == '?') start++;
    uint8_t P[256];
    size_t longest_known_match = store->longest_match;
    size_t clen = coded.size();
    for (;;) {
        if (store->complete_match || store->end) {
            secp256k1_context_destroy(ctx);
            delete [] pubs;
            delete [] privs;
            return;
        }
        if (iter == KP_CHUNK_SIZE) {
            // generate new chunk of keys
            unsigned char seed[32];
            if (!fread(seed, 1, 32, store->fp)) {
                fprintf(stderr, "unable to read from /dev/urandom; aborting\n");
                exit(1);
            }
            if (1 != secp256k1_ec_grind(ctx, pubs, privs, KP_CHUNK_SIZE, seed, nullptr)) {
                fprintf(stderr, "seed invalid; should probably try with more than one\n");
                exit(1);
            }
            iter = 0;
            // loop back since this takes awhile; we may have found a complete match at this point
            continue;
        }
        local_ctr++;
        if (local_ctr == 100000) {
            local_ctr = 0;
            size_t c = 100000 * (++store->counter);
            if (c % next_eta == 0) {
                next_eta <<= 1;
                auto now = time_ms();
                double elapsed_secs = std::chrono::duration<double>(now - store->start_time).count();
                double addresses_per_sec = double(c) / elapsed_secs;
                double exp_time = store->prob.expected_time(addresses_per_sec);
                uint64_t seconds = exp_time;
                std::string tstr = timestr(seconds);
                printf("(%zu addresses in %s; %.3f addresses/second; statistical expected time: %s)                                    \n", c, timestr(elapsed_secs).c_str(), addresses_per_sec, tstr.c_str());
            }
            switch (c) {
            // case 1000000UL:        printf("*** First million down, many more to go ... ... ... ***                                                                                                  \n"); break;
            case 100000000UL:      xprintf("*** One hundred million. Woot. Should be done in no time...! ***                                                                                         \n"); break;
            case 250000000UL:      xprintf("*** Quarter to a billion. You don't give up do you? ***                                                                                                  \n"); break;
            case 500000000UL:      xprintf("*** Half a billion! Now we just have to wait ANOTHER %s to get to a billion.                                                                             \n", timestr(std::chrono::duration<double>(time_ms() - store->start_time).count()).c_str()); break;
            case 1000000000UL:     xprintf("*** One billion! I deserve a raise. Are you gonna give up soon btw? ***                                                                                  \n"); break;
            case 10000000000UL:    xprintf("*** This is getting a little bit ridiculous. 10 billion. How much is your vanity worth anyway? ***                                                       \n"); break;
            case 100000000000UL:   xprintf("*** 100 billion. If this was one per second, you would have spent 3168 years at this point. ***                                                          \n"); break;
            case 250000000000UL:   xprintf("*** Quarter to a trillion. This seems hopeless... ***    ***                                                                                                  \n"); break;
            case 500000000000UL:   xprintf("*** We haven't found your magic phrase, but we HAVE shuffled through half a trillion bech32 addresses. There is that, right? Right? ***                                                       \n"); break;
            case 750000000000UL:   xprintf("*** Fun fact: did you know that, despite the fact we have now processed three quarters of a trillion bech32 addresses, the probability that the next address we look at is 'the one' is exactly the same as the probability that the first address we checked out was 'the one'. In other words, we have made absolutely no progress whatsoever. The estimated time to find your magic phrase is still the same as it was the first second when we started processing. Neat, huh? ***\n"); break;
            case 1000000000000UL:  xprintf("*** 1 trillion. T R I L L I O N. You've spent a trillion attempts to find a vanity address. You are like the god of self-loving vanity freaks. ***       \n"); break;
            case 10000000000000UL: xprintf("*** 10 trillion. I don't think I need to say anything else here. You sure love yourself. ***                                                             \n"); break;
            }
            if (id == 0) {
                printf(" %zu: %s\r", c, HexStr(&privs[iter<<5], &privs[(iter+1)<<5]).c_str()); fflush(stdout);
            }
            if (c == store->cap) {
                store->end = true;
                secp256k1_context_destroy(ctx);
                delete [] pubs;
                delete [] privs;
                return;
            }
        }
        // get pubkey
        Value v = Value::from_secp256k1_pubkey(&pubs[iter]);
        // Value v(u);
        // v.do_get_pubkey();
        v.do_hash160();
        size_t matches = 0;
        for (size_t i = 0; i < clen - 1; ++i) {
            matches += v.data[i] == coded[i];
        }
        matches += (v.data[clen - 1] & final_mask) == (coded[clen - 1] & final_mask);

        if (matches == clen) {
            // found a full match
            uint8_t* pc = P;
            v.do_bech32enc(&pc);
            const char* str = v.str_value().c_str();
            store->new_match(str, &privs[iter<<5], plen, true);
            secp256k1_context_destroy(ctx);
            delete [] pubs;
            delete [] privs;
            return;
        }
        if (matches > store->longest_match || (matches > SHOW_ALTS_AT && matches == store->longest_match)) {
            // found a longest match
            uint8_t* pc = P;
            v.do_bech32enc(&pc);
            const char* str = v.str_value().c_str();
            store->new_match(str, &privs[iter<<5], matches, false);
        }
        iter++;
    }
}

int main(int argc, char* const* argv)
{
    printf("SHA256 = %s\n", SHA256AutoDetect().c_str());

    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("addrtype", 't', req_arg);
    ca.add_option("processes", 'j', req_arg);
    ca.add_option("max-iters", 'x', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q');

    if (ca.m.count('h') || ca.l.size() != 1) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [-j<n>|--processes=<n>] [-x<n>|--max-iters=<n>] \"<prefix>\"\n", argv[0]);
        return 1;
    }

    const char* prefix = ca.l[0];
    size_t len = strlen(prefix);
    if (len > 32) {
        printf("restricted to 32 characters, you are using %zu\n", len);
        return 1;
    }
    for (size_t i = 0; i < len; ++i) {
        if (!in(prefix[i], CHARSET, 32)) {
            printf("the character '%c' is unavailable. bech32 allows these -> %s\n", prefix[i], CHARSET);
            return 1;
        }
    }
    // assume 32 letter combinations
    size_t letters = len;
    // for (size_t i = 1; i < len; i++) letters -= prefix[i] == '?';
    probability prob(letters, 5);
    printf("%zu letter prefix; 1/%s probability (%s%%) of encountering\n", len, prob.one_in_string().c_str(), prob.percentage().c_str());

    // decode bech32 prefix
    std::vector<uint8_t> coded_prefix;
    uint8_t final_mask;
    decode_bech32_prefix(prefix, coded_prefix, final_mask);

    size_t processes = ca.m.count('j') ? atoi(ca.m['j'].c_str()) : 1;
    privkey_store* store = new privkey_store(prob);
    store->prefix = prefix;
    if (ca.m.count('x')) store->cap = (size_t)atoll(ca.m['x'].c_str());
    std::vector<std::thread> finders;
    for (size_t i = 0; i < processes; i++) {
        finders.emplace_back(finder, i, processes, prefix, coded_prefix, final_mask, store);
    }
    for (std::thread& t : finders) t.join();
}
