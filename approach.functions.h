// Copyright (c) 2020 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef included_btcdeb_approach_functions_h_
#define included_btcdeb_approach_functions_h_

#include <vector>
#include <msenv.h>

extern "C" {
#include <kerl/kerl.h>
}

namespace approach {

extern MSEnv* env;
extern int count;
extern char** script_lines;

int fn_step(const char*);
int fn_rewind(const char*);
int fn_present(const char*);
int fn_absent(const char*);
int fn_conf(const char*);
int fn_script(const char*);
int fn_paths(const char*);

char* compl_presence(const char*, int);

} // namespace approach

#endif // included_btcdeb_approach_functions_h_
