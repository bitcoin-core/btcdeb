#ifndef included_ansicolors_h_
#define included_ansicolors_h_

// Source: https://stackoverflow.com/questions/2616906/how-do-i-output-coloured-text-to-a-linux-terminal
namespace ansi {

const std::string reset("\033[0m"); // everything back to normal

const std::string bold   ("\033[1m"); // often a brighter shade of the same color
const std::string uline  ("\033[4m");
const std::string inverse("\033[7m"); // swap fg/bg

const std::string bold_off   ("\033[21m");
const std::string uline_off  ("\033[24m");
const std::string inverse_off("\033[27m");

const std::string fg_black  ("\033[0;30m");
const std::string fg_red    ("\033[0;31m");
const std::string fg_green  ("\033[0;32m");
const std::string fg_yellow ("\033[0;33m");
const std::string fg_blue   ("\033[0;34m");
const std::string fg_magenta("\033[0;35m");
const std::string fg_cyan   ("\033[0;36m");
const std::string fg_white  ("\033[0;37m");

const std::string bg_black  ("\033[0;40m");
const std::string bg_red    ("\033[0;41m");
const std::string bg_green  ("\033[0;42m");
const std::string bg_yellow ("\033[0;43m");
const std::string bg_blue   ("\033[0;44m");
const std::string bg_magenta("\033[0;45m");
const std::string bg_cyan   ("\033[0;46m");
const std::string bg_white  ("\033[0;47m");

inline size_t length(const std::string& s) {
    size_t l = 0;
    for (size_t i = 0; s[i]; ++i) {
        char ch = s[i];
        if (ch == 033) {
            for (++i; s[i] != 'm'; ++i);
            continue;
        }
        ++l;
    }
    return l;
}

inline std::string substring(const std::string& s, size_t start, size_t length) {
    char buf[1024];
    size_t p = 0;
    size_t l = 0;
    size_t end = start + length;
    for (size_t i = 0; l < end && s[i]; ++i) {
        bool xfer = l >= start;
        if (s[i] == 033) {
            if (xfer) buf[p++] = s[i];
            for (++i; s[i] != 'm'; ++i) if (xfer) buf[p++] = s[i];
            if (xfer) buf[p++] = s[i];
            continue;
        }
        if (xfer) buf[p++] = s[i];
        ++l;
    }
    buf[p] = 0;
    return std::string(buf) + reset;
}

inline std::string trimmed_right(const std::string& s) {
    size_t len = s.length();
    if (len == 0) return s;
    size_t j;
    for (size_t i = len - 1; i > 1; --i) {
        switch (s[i]) {
            case ' ':
            case '\t':
            case '\n':
                continue;
            case 'm':
                // ansi sequence?
                j = i - 1;
                while (j > 0 && s[j] >= '0' && s[j] <= '9') --j;
                if (j > 0 && s[j] == ';') {
                    --j;
                    while (j > 0 && s[j] >= '0' && s[j] <= '9') --j;
                    if (j > 0 && s[j] == ']') {
                        if (s[j] == 033) {
                            i = j;
                            continue;
                        }
                    }
                }
                // nope, not an ansi sequence; we're done! fall-through
            default:
                return s.substr(0, i + 1);
        }
    }
    // the entire string was whitespace and/or ansi codes
    return "";
}

} // namespace ansi

#endif // included_ansicolors_h_
