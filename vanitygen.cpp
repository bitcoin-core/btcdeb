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

typedef std::chrono::milliseconds milliseconds;

inline milliseconds time_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch());
}

bool quiet = false;

const char* bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
size_t bech32_char_count = 32;

inline bool in(char c, const char* v, size_t l) {
    for (size_t i = 0; i < l; ++i) if (v[i] == c) return true;
    return false;
}

struct privkey_store {
    milliseconds start_time;
    std::vector<std::vector<uint8_t>> v;
    std::mutex mtx;
    size_t longest_match = 5;
    uint64_t iprob;
    size_t cap = 0;
    bool complete_match = false;
    bool end = false;
    FILE* fp = nullptr;
    std::atomic<size_t> counter;

    privkey_store(uint64_t iprob_in) : iprob(iprob_in) {
        fp = fopen("/dev/urandom", "rb");
        assert(fp && "/dev/urandom required");
        start_time = time_ms();
    }

    inline void new_match(const char* str, const std::vector<uint8_t>& u, size_t longest, bool complete) {
        std::lock_guard<std::mutex> guard(mtx);
        if (!(longest > longest_match || (longest > 6 && longest == longest_match))) return;
        if (longest_match == longest) {
            printf("* alternative match: %s\n", str);
            printf("* privkey:           %s\n", HexStr(u).c_str());
            return;
        }
        longest_match = longest;
        complete_match = complete;
        printf("* new %s match: %s\n", complete ? "full" : "longest", str);
        printf("* privkey:%s        %s\n", complete ? "" :     "   ", HexStr(u).c_str());
    }

    // inline void add(const std::vector<uint8_t>& privkey) {
    //     while (v.size() >= 100) {}
    //     {
    //         std::lock_guard<std::mutex> guard(mtx);
    //         v.push_back(privkey);
    //     }
    // }
    inline std::vector<uint8_t> pop() {
        for (;;) {
            while (v.size() == 0) {
                std::vector<uint8_t> x;
                x.resize(32);
                if (fp) {
                    // we don't wait for random keys, we just make one ourselves
                    if (!fread(x.data(), 1, 32, fp)) {
                        fprintf(stderr, "Failed to read random data; aborting\n");
                        exit(1);
                    }
                    return x;
                }
            }
            {
                std::lock_guard<std::mutex> guard(mtx);
                if (v.size() == 0) continue;
                std::vector<uint8_t> u = v[0];
                v.erase(v.begin());
                return u;
            }
        }
    }
};

// void privkey_spawner(privkey_store* store) {
//     FILE* fp = store->fp = fopen("/dev/urandom", "rb");
//     assert(fp && "/dev/urandom required");
//     std::vector<uint8_t> x;
//     x.resize(32);
//     for (;;) {
//         if (store->complete_match) {
//             fclose(fp);
//             return;
//         }
//         fread(x.data(), 1, 32, fp);
//         store->add(x);
//     }
// }

bool prefixcmp(const char* prefix, const char* str, size_t plen) {
    for (size_t i = 0; i < plen; ++i) if (prefix[i] != '?' && prefix[i] != str[i]) return false;
    return true;
}

inline void inc(std::vector<uint8_t>& u, int amt) {
    size_t i = 0;
    while (i < 32 && u[i] > 0xff - amt) {
        u[i] += amt;
        i++;
        amt = 1;
    }
    if (i < 32) u[i] += amt;
}

std::string timestr(int seconds) {
    int minutes = seconds / 60;
    seconds %= 60;
    int hours = minutes / 60;
    minutes %= 60;
    int days = hours / 24;
    hours %= 24;
    int weeks = days/7;
    days %= 7;
    std::string s = "";
    if (weeks > 0) s += strprintf("%d week%s", weeks, weeks == 1 ? "" : "s");
    if (days > 0) s += strprintf("%s%d day%s", weeks ? ", " : "", days, days == 1 ? "" : "s");
    if (hours > 0 && weeks == 0) s += strprintf("%s%d hour%s", weeks+days ? ", " : "", hours, hours == 1 ? "" : "s");
    if (minutes > 0 && weeks + days == 0) s += strprintf("%s%d min%s", hours ? ", " : "", minutes, minutes == 1 ? "" : "s");
    if (seconds > 0 && weeks + days + hours == 0) s += strprintf("%s%d second%s", minutes ? ", " : "", seconds, seconds == 1 ? "" : "s");
    return s;
}

std::string timestr(std::chrono::duration<int> milliseconds) {
    return timestr(milliseconds.count() / 1000);
}

static const char* spaces = "                                                                    ";

void finder(size_t id, int step, const std::vector<uint8_t>& base, const char* prefix, privkey_store* store) {
    size_t plen = strlen(prefix);
    std::vector<uint8_t> u = base;
    // shift
    inc(u, id);
    size_t local_ctr = 0;
    for (;;) {
        if (store->complete_match || store->end) {
            return;
        }
        local_ctr++;
        if (local_ctr == 100000) {
            local_ctr = 0;
            size_t c = 100000 * (++store->counter);
            if (c % 1000000000 == 0) {
                auto now = time_ms();
                double elapsed_secs = std::chrono::duration<double>(now - store->start_time).count();
                double addresses_per_sec = double(c) / elapsed_secs;
                double exp_time = store->iprob / addresses_per_sec; // h / (h/s) = h * (s/h) = s
                int seconds = exp_time;
                std::string tstr = timestr(seconds);
                printf("(%zu addresses in %s; %.3f addresses/second; statistical expected time: %s)                                    \n", c, timestr(elapsed_secs).c_str(), addresses_per_sec, tstr.c_str());
            }
            switch (c) {
            // case 1000000UL:        printf("*** First million down, many more to go ... ... ... ***                                                                                                  \n"); break;
            case 100000000UL:      printf("*** One hundred million. Woot. Should be done in no time...! ***                                                                                         \n"); break;
            case 250000000UL:      printf("*** Quarter to a billion. You don't give up do you? ***                                                                                                  \n"); break;
            case 500000000UL:      printf("*** Half a billion! Now we just have to wait ANOTHER %s to get to a billion.                                                                             \n", timestr(std::chrono::duration<double>(time_ms() - store->start_time).count()).c_str()); break;
            case 1000000000UL:     printf("*** One billion! I deserve a raise. Are you gonna give up soon btw? ***                                                                                  \n"); break;
            case 10000000000UL:    printf("*** This is getting a little bit ridiculous. 10 billion. How much is your vanity worth anyway? ***                                                       \n"); break;
            case 100000000000UL:   printf("*** 100 billion. If this was one per second, you would have spent 3168 years at this point. ***                                                          \n"); break;
            case 1000000000000UL:  printf("*** 1 trillion. T R I L L I O N. You've spent a trillion attempts to find a vanity address. You are like the god of self-loving vanity freaks. ***       \n"); break;
            case 10000000000000UL: printf("*** 10 trillion. I don't think I need to say anything else here. You sure love yourself. ***                                                             \n"); break;
            }
            if (id == 0) {
                printf("%zu: %s\r", c, HexStr(u).c_str()); fflush(stdout);
            }
            if (c == store->cap) {
                store->end = true;
                return;
            }
        }
        Value v(u);
        v.do_get_pubkey();
        v.do_hash160();
        v.do_bech32enc();
        const char* str = v.str_value().c_str();
        // first 3 letters are bc1; we do not test for this as it slows this down
        // assert(str[0] == 'b' && str[1] == 'c' && str[2] == '1');
        str = &str[3];
        if (prefixcmp(prefix, str, plen)) {
            // found a match
            store->new_match(&str[-3], u, plen, true);
            return;
        }
        size_t mlen = strlen(prefix);
        size_t mlen2 = strlen(str);
        if (mlen > mlen2) mlen = mlen2;
        for (size_t i = 0; i < mlen; ++i) {
            if (prefix[i] != '?' && str[i] != prefix[i]) {
                if (i > store->longest_match || (i > 6 && i == store->longest_match)) {
                    store->new_match(&str[-3], u, i, false);
                }
                break;
            }
        }
        inc(u, step);
    }
}

std::string iprob_perc(uint64_t iprob) {
    std::string s = "0.";
    double d = 1.0 / iprob;
    d *= 100;
    assert(d < 1.0);
    while (d < 1.0) {
        s += "0";
        d *= 10;
    }
    d *= 10;
    s += std::to_string(int(d));
    return s;
}

int main(int argc, char* const* argv)
{
    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("addrtype", 't', req_arg);
    ca.add_option("processes", 'j', req_arg);
    ca.add_option("max-iters", 'x', req_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q');

    if (ca.m.count('h') || ca.l.size() != 1) {
        fprintf(stderr, "syntax: %s [-q|--quiet] [-j<n>|--processes=<n>] [-x<n>|--max-iters=<n>] \"<prefix>\"\n<prefix> may contain the character ? any number of times to indicate wildcard character, e.g. '??foo?bar'\n", argv[0]);
        return 1;
    }

    const char* prefix = ca.l[0];
    if (prefix[0] != '?' && prefix[0] != 'q') {
        printf("all bech32 adresses must begin with a 'q'\n");
        return 1;
    }
    if (prefix[1] != '?' && !in(prefix[1], "qmpzrx26skavyhf", 15)) {
        printf("warning: unsure if '%c' ever occurs as second letter (I've seen qmpzrx26skavyhf)\n", prefix[1]);
    }
    size_t len = strlen(prefix);
    for (size_t i = 0; i < len; ++i) {
        if (prefix[i] != '?' && !in(prefix[i], bech32_chars, bech32_char_count)) {
            printf("the character '%c' is unavailable. bech32 allows these -> %s\n", prefix[i], bech32_chars);
            return 1;
        }
    }
    // assume 14 combinations for letter 2 and 32 for all others,
    uint64_t iprob = prefix[1] == '?' ? 1 : 14;
    for (size_t i = 2; i < len; i++) {
        if (prefix[i] != '?') iprob *= 32;
    }
    printf("%zu letter prefix; 1/%llu probability (%s%%) of encountering\n", len, iprob, iprob_perc(iprob).c_str());

    size_t processes = ca.m.count('j') ? atoi(ca.m['j'].c_str()) : 1;
    // bc1... is he bech32 encoding of the hash160 of the pubkey
    // so we need to:
    // 1. make a new random private key
    // 2. get its public key equivalent
    // 3. get the pubkey hash160
    // 4. get the pubkey hash160 bech32 encoding
    // 5. check the prefix
    // since randomness is slow, we dedicate a thread to simply spewing out random 32 byte values
    // and use semaphores to pull them out
    privkey_store* store = new privkey_store(iprob);
    if (ca.m.count('x')) store->cap = (size_t)atoll(ca.m['x'].c_str());
    // std::thread pks(privkey_spawner, store);
    std::vector<std::thread> finders;
    std::vector<uint8_t> base = store->pop();
    for (size_t i = 0; i < processes; i++) {
        finders.emplace_back(finder, i, processes, base, prefix, store);
    }
    // pks.join();
    for (std::thread& t : finders) t.join();
}
