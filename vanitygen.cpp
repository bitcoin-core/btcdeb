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

std::string hrp = "bc";
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
    final_mask = 0xff << ((8 - ((5 * len) & 0x07)) & 0x07);
}

#define KP_CHUNK_SIZE 1024
#define SHOW_ALTS_AT  4     // start showing alternatives at this many matching letters

struct probability {
    size_t letters, bits;
    probability(size_t letters_in, size_t bits_in) : letters(letters_in), bits(bits_in) {}
    probability(const probability& prob) : letters(prob.letters), bits(prob.bits) {}
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

void count_bits(const uint8_t* show, const uint8_t* compare, size_t len, uint8_t final_mask, size_t& matches, size_t& count) {
    matches = count = 0;
    bool matching = false;
    size_t i;
    for (i = 0; i < len - 1; ++i) {
        uint8_t a = show[i] ^ compare[i];
        for (size_t j = 1; j < 256; j <<= 1) {
            count++;
            matches += !(a & j);
        }
    }
    uint8_t a = show[len-1] ^ compare[len-1];
    for (size_t j = 1; j < 256; j <<= 1) {
        if (final_mask & j) {
            count++;
            matches += !(a & j);
        }
    }
}

void ansi_print_compare_bits(const uint8_t* show, const uint8_t* compare, size_t len, uint8_t final_mask) {
    bool matching = false;
    size_t i;
    std::string wrong = ansi::fg_red + ansi::bold;
    std::string right = ansi::fg_green + ansi::bold;
    printf("%s", wrong.c_str());
    #define match_and_put() {\
        if (a & j) { \
            if (matching) printf("%s", wrong.c_str()); \
            matching = false; \
        } else if (!matching) { \
            printf("%s", right.c_str()); \
            matching = true; \
        } \
        putchar('1' - !(show[i] & j)); \
    }

    for (i = 0; i < len - 1; ++i) {
        uint8_t a = show[i] ^ compare[i];
        for (size_t j = 1; j < 256; j <<= 1) {
            match_and_put();
        }
        putchar(' ');
    }
    uint8_t a = show[len-1] ^ compare[len-1];
    for (size_t j = 1; j < 256; j <<= 1) {
        if (final_mask & j) match_and_put();
    }
    printf("%s", ansi::reset.c_str());
}

FILE* dev_urandom = nullptr;
milliseconds start_time;
std::atomic<size_t> counter;

struct privkey_store {
    const char* prefix;
    std::vector<std::vector<uint8_t>> v;
    std::mutex mtx;
    size_t longest_match = 3;
    size_t longest_match_bits = 24;
    probability prob;
    size_t cap = 0;
    bool complete_match = false;
    bool end = false;

    privkey_store(probability& prob_in) : prob(prob_in) {}

    inline void new_match(const char* str, const uint8_t* u, size_t longest, size_t longest_bits, bool complete) {
        std::lock_guard<std::mutex> guard(mtx);
        if (longest < longest_match) return;
        // if (!(longest > longest_match || (longest > SHOW_ALTS_AT && longest == longest_match))) return;
        Value p(std::vector<uint8_t>(u, u + 32));
        p.data.push_back(0x01);
#ifdef ENABLE_DANGEROUS
        p.do_encode_wif();
#endif
        if (longest_match == longest && longest_bits <= longest_match_bits) {
            printf("\n* alternative match: ");
            ansi_print_compare(str, prefix, 2 + hrp.size());
            printf("\n* privkey:           %s\n", p.str_value().c_str()); // HexStr(u, u + 32).c_str());
            return;
        }
        if (longest_match_bits < longest_bits) longest_match_bits = longest_bits;
        longest_match = longest;
        complete_match = complete;
        printf("\n* new %s match: ", complete ? "full" : "longest");
        ansi_print_compare(str, prefix, 2 + hrp.size());
        printf("\n* privkey:%s        %s\n", complete ? "" :     "   ", p.str_value().c_str()); // HexStr(u, u + 32).c_str());
    }
};

struct query {
    const char* prefix;
    size_t plen, clen;
    std::vector<uint8_t> coded;
    uint8_t final_mask;
    privkey_store* store;
    query(const char* prefix_in, std::vector<uint8_t>& coded_in, uint8_t final_mask_in, privkey_store* store_in)
    : prefix(prefix_in)
    , plen(strlen(prefix_in))
    , clen(coded_in.size())
    , coded(coded_in)
    , final_mask(final_mask_in)
    , store(store_in) {}
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

#define xprintf(args...) printf("%s ", shorttimestr(std::chrono::duration<double>(time_ms() - start_time).count()).c_str()); printf(args)

void finder(size_t id, int step, std::vector<query*>* queries) {
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

    secp256k1_pubkey* pubs = new secp256k1_pubkey[KP_CHUNK_SIZE];
    unsigned char* privs = new unsigned char[32 * KP_CHUNK_SIZE];
    size_t iter = KP_CHUNK_SIZE;
    size_t local_ctr = 0;
    size_t next_eta = 1000000000;

    for (;;) {
        if (iter == KP_CHUNK_SIZE) {
            // generate new chunk of keys
            unsigned char seed[32];
            int scounter = 500;
            while (1) {
                if (!fread(seed, 1, 32, dev_urandom)) {
                    fprintf(stderr, "unable to read from /dev/urandom; aborting\n");
                    exit(1);
                }
                if (1 == secp256k1_ec_grind(ctx, pubs, privs, KP_CHUNK_SIZE, seed, nullptr)) {
                    break;
                }
                scounter--;
                if (scounter <= 0) {
                    fprintf(stderr, "unable to grind key pairs; aborting\n");
                    exit(1);
                }
            }
            iter = 0;
            // loop back since this takes awhile; we may have found a complete match at this point
            continue;
        }
        local_ctr++;
        if (local_ctr == 100000) {
            local_ctr = 0;
            size_t c = 100000 * (++counter);
            if (c % next_eta == 0) {
                next_eta *= 3;
                auto now = time_ms();
                double elapsed_secs = std::chrono::duration<double>(now - start_time).count();
                double addresses_per_sec = double(c) / elapsed_secs;
                double exp_time = (*queries)[0]->store->prob.expected_time(addresses_per_sec);
                double combinations_per_sec = addresses_per_sec * queries->size();
                uint64_t seconds = exp_time;
                std::string tstr = timestr(seconds);
                static bool explained = false;
                if (explained) {
                    printf("(%zu addresses in %s; %.3f combinations/second; statistical expected time: %s)                                   \n", c, timestr(elapsed_secs).c_str(), combinations_per_sec, tstr.c_str());
                } else {
                    printf("(%zu addresses in %s; %.3f combinations*/second; statistical expected time: %s) [* 1 combination = %zu address%s]                                   \n", c, timestr(elapsed_secs).c_str(), combinations_per_sec, tstr.c_str(), queries->size(), queries->size() == 1 ? "" : "es");
                    explained = true;
                }
            }
            switch (c) {
            // case 1000000UL:        printf("*** First million down, many more to go ... ... ... ***                                                                                                  \n"); break;
            case 100000000UL:      xprintf("*** One hundred million. Woot. Should be done in no time...! ***                                                                                         \n"); break;
            case 250000000UL:      xprintf("*** Quarter to a billion. You don't give up do you? ***                                                                                                  \n"); break;
            case 500000000UL:      xprintf("*** Half a billion! Now we just have to wait ANOTHER %s to get to a billion.                                                                             \n", timestr(std::chrono::duration<double>(time_ms() - start_time).count()).c_str()); break;
            case 1000000000UL:     xprintf("*** One billion! I deserve a raise. Are you gonna give up soon btw? ***                                                                                  \n"); break;
            case 10000000000UL:    xprintf("*** This is getting a little bit ridiculous. 10 billion. How much is your vanity worth anyway? ***                                                       \n"); break;
            case 42000000000UL:    xprintf("*** 42 billion. If this was distance traveled in meters, you would have reached Venus. ***                                                           \n"); break;
            case 78000000000UL:    xprintf("*** 78 billion. [distance in meters] Welcome to Mars. ***                                                                                \n"); break;
            case 91500000000UL:    xprintf("*** 91.5 billion. [distance in meters] Welcome to Mercury. ***                                                                                \n"); break;
            case 100000000000UL:   xprintf("*** 100 billion. If this was one address per second, you would have spent 3168 years at this point. ***                                                          \n"); break;
            case 146000000000UL:   xprintf("*** 146 billion. If this was distance traveled in meters, you would have now reached the sun, presuming distance to earth was the closest (perihelion, early January)."); break;
            case 152000000000UL:   xprintf("*** 152 billion. If this was distance traveled in meters, you would have now reached the sun, presuming distance to earth was the FARTHEST (aphelion, early July)."); break;
            case 197600250000UL:   xprintf("*** 197.6 billion. If we were traveling back in time at a pace of 1 address = 1 day, we would have now reached the beginning of the phanerozoic eon (541 mya (megayear = 1,000,000 years) in the past) and returned into the proterozoic eon ***\n"); break;
            case 250000000000UL:   xprintf("*** Quarter to a trillion. This seems hopeless, but let's not give up...!    ***                                                                                                  \n"); break;
            case 500000000000UL:   xprintf("*** We haven't found your magic phrase, but we HAVE shuffled through half a trillion bech32 addresses. There is that, right? Right? ***                                                       \n"); break;
            case 630000000000UL:   xprintf("*** 630 billion. [distance in meters] Welcome to Jupiter. ***                                                                                \n"); break;
            case 750000000000UL:   xprintf("*** Fun fact: did you know that, despite the fact we have now processed three quarters of a trillion bech32 addresses, the probability that the next address we look at is 'the one' is exactly the same as the probability that the first address we checked out was 'the one'. In other words, we have made absolutely no progress whatsoever. The estimated time to find your magic phrase is still the same as it was the first second when we started processing. Neat, huh? ***\n"); break;
            case 913125000000UL:   xprintf("*** 913.1 billion. [traveling back in time 1 addr=1 day] We have now passed through the proterozoic eon (starting 2,500 mya in the past) and are entering into the archean eon. It will last for 1,500 mya ***\n"); break;
            case 1000000000000UL:  xprintf("*** 1 trillion. T R I L L I O N. You've spent a trillion attempts to find a vanity address. You are like the god of self-loving vanity freaks. ***       \n"); break;
            case 1287000000000UL:   xprintf("*** 1.287 trillion. [distance in meters] Welcome to Saturn. ***                                                                                \n"); break;
            case 1461000000000UL:  xprintf("*** 1.461 trillion. [traveling back in time 1 addr=1 day] We have returned to the beginning of the archean eon, 4 billion years ago. We are passing into the first eon of earth's history, the Hadean eon ***\n"); break;
            case 1658235000000UL:  xprintf("*** 1.658 trillion. [traveling back in time 1 addr=1 day] We have returned to the beginning of the Hadean eon, 4.5 billion years ago. Earth has not yet formed (end of earth geochronology series) ***\n"); break;
            case 2000000000000UL:  xprintf("*** 2 trillion. That's a 2 followed by 12 zeroes. ***                                                                                                     \n"); break;
            case 2730000000000UL:  xprintf("*** 2.73 trillion. [distance in meters] Welcome to Uranus. ***                                                                                \n"); break;
            case 4357500000000UL:  xprintf("*** 4.3575 trillion. [distance in meters] Welcome to Neptune. ***                                                                                \n"); break;
            case 5772000000000UL:  xprintf("*** 5.772 trillion. [distance in meters] Welcome to Pluto. ***                                                                                \n"); break;
            case 10000000000000UL: xprintf("*** 10 trillion. I don't think I need to say anything else here. You sure love yourself. ***                                                             \n"); break;
            case 31557600000000UL: xprintf("*** 31.5576 trillion. If 1 address equaled 1 second, you would have now passed 1 mya (megayear = 1,000,000 years), assuming 1 year = 365.25 days ***                      \n"); break;
            case 37200000000000UL: xprintf("*** 37.2 trillion. For every cell in your body, you have now created a private and public key pair, calculated the public key's hash160, and compared it to the corresponding bech32 output. And you have failed to find an exact match each and every time. ***\n"); break;
            case 40000000000000UL: xprintf("*** 40 trillion. [distance in KILOmeters] Welcome to Alpha Centauri. ***                                                                                \n"); break;
            }
            if (id == 0) {
                printf(" %zu\r", c); fflush(stdout);
            }
            if ((*queries)[0]->store->cap && c >= (*queries)[0]->store->cap) {
                (*queries)[0]->store->end = true;
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
        for (query* q : *queries) {
            size_t clen = q->clen;
            std::vector<uint8_t>& coded = q->coded;
            uint8_t final_mask = q->final_mask;
            privkey_store* store = q->store;

            if (store->complete_match || store->end) {
                secp256k1_context_destroy(ctx);
                delete [] pubs;
                delete [] privs;
                return;
            }
            size_t matches = 0;
            for (size_t i = 0; i < clen - 1; ++i) {
                matches += v.data[i] == coded[i];
            }
            matches += (v.data[clen - 1] & final_mask) == (coded[clen - 1] & final_mask);

            if (matches == clen) {
                // found a full match
                v.do_bech32enc(hrp);
                const char* str = v.str_value().c_str();
                store->new_match(str, &privs[iter<<5], q->plen, 0, true);
                secp256k1_context_destroy(ctx);
                delete [] pubs;
                delete [] privs;
                return;
            }

            if (matches > store->longest_match || (matches > SHOW_ALTS_AT && matches == store->longest_match)) {
                // found a potential longest match
                size_t matched_bits, count;
                count_bits(v.data.data(), coded.data(), clen, final_mask, matched_bits, count);
                if (matched_bits >= store->longest_match_bits) {
                    v.do_bech32enc(hrp);
                    const char* str = v.str_value().c_str();
                    store->new_match(str, &privs[iter<<5], matches, matched_bits, false);
                    printf("* bits:              ");
                    ansi_print_compare_bits(v.data.data(), coded.data(), clen, final_mask);
                    printf(" [%zu/%zu]\n", matched_bits, count);
                }
            }
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
    ca.add_option("hrp", 'r', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q');

    if (ca.m.count('h') || ca.l.size() == 0) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [--hrp=<string>] [-j<n>|--processes=<n>] [-x<n>|--max-iters=<n>] \"<prefix>\" [\"<prefix2>\" [...]]\n", argv[0]);
        fprintf(stderr, "you can search for any number of prefixes by simply listing them; the system will, for each keypair/hash160 entry, compare each prefix and report best matches for each prefix. note that the scan will stop if ANY of the prefixes is found in full\n");
        return 1;
    }

    dev_urandom = fopen("/dev/urandom", "rb");
    assert(dev_urandom && "/dev/urandom required");
    start_time = time_ms();

    if (ca.m.count('r')) hrp = ca.m['r'];

    std::vector<query*> queries;
    for (const char* prefix : ca.l) {
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
        privkey_store* store = new privkey_store(prob);
        store->prefix = prefix;
        if (ca.m.count('x')) store->cap = (size_t)atoll(ca.m['x'].c_str());

        queries.push_back(new query(prefix, coded_prefix, final_mask, store));
    }

    size_t processes = ca.m.count('j') ? atoi(ca.m['j'].c_str()) : 1;
    if (processes == 1) {
        // run on main thread
        finder(0, 1, &queries);
    } else {
        // spawn and join
        std::vector<std::thread> finders;
        for (size_t i = 0; i < processes; i++) {
            finders.emplace_back(finder, i, processes, &queries);
        }
        for (std::thread& t : finders) t.join();
    }
}
