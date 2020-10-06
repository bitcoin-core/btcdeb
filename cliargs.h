// Copyright (c) 2017-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLIARGS_H
#define BITCOIN_CLIARGS_H

#include <map>
#include <vector>
#include <set>

#include <cstring>
#include <getopt.h>

#include <tinyformat.h>

enum cliarg_type {
    no_arg = no_argument,
    req_arg = required_argument,
    opt_arg = optional_argument,
};

struct cliopt {
    char* longname;
    char shortname;
    cliarg_type type;
    cliopt(const char* longname_in, const char shortname_in, cliarg_type type_in)
    : longname(strdup(longname_in))
    , shortname(shortname_in)
    , type(type_in)
    {}
    ~cliopt() { free(longname); }
    struct option get_option(std::string& opt) {
        opt += strprintf("%c%s", shortname, type == no_arg ? "" : ":");
        return {longname, type, nullptr, shortname};
    }
};

struct cliargs {
    std::map<char, std::string> m;
    std::vector<const char*> l;
    std::vector<cliopt*> long_options;

    ~cliargs() {
        while (!long_options.empty()) {
            delete long_options.back();
            long_options.pop_back();
        }
    }
    void add_option(const char* longname, const char shortname, cliarg_type t) {
        long_options.push_back(new cliopt(longname, shortname, t));
    }
    void parse(int argc, char* const* argv) {
        struct option long_opts[long_options.size() + 1];
        std::string opt = "";
        for (size_t i = 0; i < long_options.size(); i++) {
            long_opts[i] = long_options[i]->get_option(opt);
        }
        long_opts[long_options.size()] = {0,0,0,0};
        int c;
        int option_index = 0;
        for (;;) {
            c = getopt_long(argc, argv, opt.c_str(), long_opts, &option_index);
            if (c == -1) {
                break;
            }
            if (optarg) {
                m[c] = optarg;
            } else {
                m[c] = "1";
            }
        }
        while (optind < argc) {
            l.push_back(argv[optind++]);
        }
    }
};

std::string string_from_file(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("unable to open path " + path);
    char* buf = (char*)malloc(128);
    size_t cap = 128;
    size_t idx = 0;
    long count;
    while (0 < (count = fread(&buf[idx], 1, cap - idx, fp))) {
        idx += count;
        if (idx < cap) break;
        cap <<= 1;
        buf = (char*)realloc(buf, cap);
    }
    buf[idx] = 0;
    std::string r = buf;
    free(buf);
    fclose(fp);
    return r;
}

/**
 * Parse a comma and/or space separated list of inputs into an existing set.
 */
inline void delimiter_set(const std::string& input, std::set<std::string>& output)
{
    size_t len = input.size();
    std::string s;
    for (size_t j = 0; j <= len; ++j) {
        if (j == len || input[j] == ',' || input[j] == ' ') {
            if (s.empty()) continue;
            output.insert(s);
            s.clear();
        } else s += tolower(input[j]);
    }
}

#endif // BITCOIN_CLIARGS_H
