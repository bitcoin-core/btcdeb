// Copyright (c) 2020 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdio>
#include <unistd.h>
#include <inttypes.h>

#include <instance.h>

#include <tinyformat.h>

#include <cliargs.h>

#include <approach.functions.h>

#include <string>
#include <vector>

#include <msenv.h>

#include <config/bitcoin-config.h>

bool quiet = false;
bool pipe_in = false;  // xxx | approach
bool pipe_out = false; // approach xxx > file

inline bool checkenv(const std::string& flag, bool fallback = false) {
    const auto& v = std::getenv(flag.c_str());
    return v ? strcmp("0", v) : fallback;
}

int main(int argc, char* const* argv)
{
    ECCVerifyHandle evh;
    pipe_in = !isatty(fileno(stdin)) || std::getenv("DEBUG_SET_PIPE_IN");
    pipe_out = !isatty(fileno(stdout)) || std::getenv("DEBUG_SET_PIPE_OUT");
    if (pipe_in || pipe_out) btc_logf = btc_logf_dummy;

    cliargs ca;
    ca.add_option("help", 'h', no_arg);
    ca.add_option("quiet", 'q', no_arg);
    ca.add_option("version", 'v', no_arg);
    ca.parse(argc, argv);
    quiet = ca.m.count('q') || pipe_in || pipe_out;

    if (ca.m.count('h')) {
        fprintf(stderr, "Syntax: %s [-v|--version] [-q|--quiet] [<script>]\n", argv[0]);
        fprintf(stderr, "If executed with no arguments, an empty script with no policies is provided\n");
        return 0;
    } else if (ca.m.count('v')) {
        printf("approach (\"The Bitcoin Policy Debugger\") version %d.%d.%d\n", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION);
        return 0;
    } else if (!quiet) {
        btc_logf("approach %d.%d.%d -- type `%s -h` for start up options\n", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION, argv[0]);
    }

    COMPILER_CTX.SymbolicOutputs = true;

    char* script_str = nullptr;
    if (pipe_in) {
        char buf[1024];
        if (!fgets(buf, 1024, stdin)) {
            fprintf(stderr, "warning: no input\n");
        }
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
        script_str = strdup(buf);
    } else if (ca.l.size() > 0) {
        script_str = strdup(ca.l[0]);
        ca.l.erase(ca.l.begin(), ca.l.begin() + 1);
    }
    approach::env = new MSEnv(script_str ?: "");
    if (script_str) free(script_str);
    // std::vector<std::string> outcomes;
    if (approach::fn_paths("")) return 1;

    if (pipe_in || pipe_out) {
        return 0; // TODO: do something less unuseful
    } else {
        kerl_set_history_file(".approach_history");
        kerl_set_repeat_on_empty(true);
        kerl_set_comment_char('#');
        // kerl_register("step", approach::fn_step, "Inspect the next combination.");
        // kerl_register("rewind", approach::fn_rewind, "Inspect the previous combination.");
        kerl_register("present", approach::fn_present, "Inspect policy for case where a given element is confirmed available.");
        kerl_register("absent", approach::fn_absent, "Inspect policy for case where a given element is confirmed unavailable.");
        kerl_register("conf", approach::fn_conf, "Set the confirmation count (used to activate 'older' entries) to the given block height.");
        kerl_register("script", approach::fn_script, "Display the Bitcoin Script version.");
        kerl_register("paths", approach::fn_paths, "Display the available paths.");
        kerl_set_completor("present", approach::compl_presence, true);
        kerl_set_completor("absent", approach::compl_presence, true);
        kerl_register_help("help");
        if (!quiet) btc_logf("%zu path policy with %zu elements loaded. type `help` for usage information\n", approach::env->m_situation.m_solutions.size(), approach::env->m_situation.m_elements.size());
        if (!quiet) {
            for (const auto& s : approach::env->m_situation.m_elements) btc_logf(" %s", s.c_str());
            btc_logf("\n");
        }
        // if (env->curr_op_seq < count) {
        //     printf("%s\n", script_lines[env->curr_op_seq]);
        // }
        kerl_run("appr> ");
    }
}
