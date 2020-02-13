// Copyright (c) 2020 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <approach.functions.h>
#include <value.h>

namespace approach {

MSEnv* env;
int count = 0;
char** script_lines;

#define fail(msg...) do { fprintf(stderr, msg); return 0; } while (0)

int fn_step(const char* arg) {
    // if (env->done) fail("at end of script\n");
    // if (!instance.step()) fail("error: %s\n", instance.error_string().c_str());
    // print_dualstack();
    // if (env->curr_op_seq < count) {
    //     printf("%s\n", script_lines[env->curr_op_seq]);
    // }
    return 0;
}

int fn_rewind(const char* arg) {
    // if (instance.at_start()) fail("error: no history to rewind\n");
    // if (!instance.rewind()) fail("error: failed to rewind; this is a bug\n");
    // print_dualstack();
    // if (env->curr_op_seq < count) {
    //     printf("%s\n", script_lines[env->curr_op_seq]);
    // }
    return 0;
}

int fn_script(const char* arg) {
    CScript script = env->m_root.m_node->ToScript(COMPILER_CTX);
    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    std::vector<uint8_t> vchPushValue;

    int i = 0;
    it = script.begin();
    while (script.GetOp(it, opcode, vchPushValue)) {
        ++i;
        printf("#%04d ", i);
        if (vchPushValue.size() > 0) {
            printf("%s", HexStr(vchPushValue.begin(), vchPushValue.end()).c_str());
        } else {
            printf("%s", GetOpName(opcode));
        }
        printf("\n");
    }
    return 0;
}

int fn_paths(const char* arg) {
    env->m_situation.m_solutions.clear();
    if (env->m_root.m_node && !env->m_root.iterate(env->m_situation)) {
        fprintf(stderr, "error: failed to iterate over miniscript\n");
        return 1;
    }
    size_t i = 0;
    for (const auto& s : env->m_situation.m_solutions) {
        ++i;
        printf("#%03zu %s\n", i, Abbreviate(s.m_description).c_str());
    }
    return 0;
}

int toggle(const char* arg, Availability avail) {
    size_t argc;
    char** argv;
    if (kerl_make_argcv(arg, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc != 1) {
        printf("syntax: present <name>\n");
        printf("e.g. for the policy or(pk(a),pk(b)), you could say \"present a\" to satisfy the policy.\n");
        kerl_free_argcv(argc, argv);
        return 0;
    }

    if (env->m_situation.m_inventory.count(argv[0]) && env->m_situation.m_inventory[argv[0]] == avail) {
        printf("- %s\n", argv[0]);
        env->m_situation.m_inventory.erase(argv[0]);
    } else {
        printf("+ %s\n", argv[0]);
        env->m_situation.m_inventory[argv[0]] = avail;
    }
    kerl_free_argcv(argc, argv);
    env->PrintTree();
    return 0;
}

int fn_present(const char* arg) {
    return toggle(arg, Availability::YES);
}

int fn_absent(const char* arg) {
    return toggle(arg, Availability::NO);
}

int fn_conf(const char* arg) {
    size_t argc;
    char** argv;
    if (kerl_make_argcv(arg, &argc, &argv)) {
        printf("user abort\n");
        return -1;
    }
    if (argc != 1) {
        printf("syntax: conf <block count>\n");
        printf("e.g. for the policy older(1008), you could say \"conf 1009\" to satisfy the policy (-1 means \"unknown\").\n");
        kerl_free_argcv(argc, argv);
        return 0;
    }

    int conf = atoi(argv[0]);
    kerl_free_argcv(argc, argv);
    if (conf < -1) {
        printf("invalid confirmation count: must be greater than -1, where -1 means \"unknown\"\n");
        return -1;
    }
    env->m_confirmations = conf;
    env->PrintTree();
    return 0;
}

char* compl_presence(const char* text, int continued) {
    static int list_index, len;
    const char *name;

    /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */
    if (!continued) {
        list_index = -1;
        len = strlen(text);
    }

    /* Return the next name which partially matches from the names list. */
    auto s = env->m_situation.m_elements;
    auto v = std::vector<std::string>(s.begin(), s.end());
    for (++list_index; list_index < v.size(); ++list_index) {
        name = v[list_index].c_str();

        if (strncasecmp(name, text, len) == 0)
            return strdup(name);
    }

    /* If no names matched, then return NULL. */
    return (char *)NULL;
}

} // namespace approach
