#ifndef included_btcdeb_functions_h_
#define included_btcdeb_functions_h_

#include <vector>
#include <debugger/interpreter.h>
#include <instance.h>

extern "C" {
#include <kerl/kerl.h>
}

extern InterpreterEnv* env;
extern Instance instance;
extern int count;
extern char** script_lines;

int fn_step(const char*);
int fn_rewind(const char*);
int fn_exec(const char*);
int fn_stack(const char*);
int fn_altstack(const char*);
int fn_vfexec(const char*);
int fn_print(const char*);
int fn_tf(const char*);
char* compl_exec(const char*, int);
char* compl_tf(const char*, int);
int print_stack(std::vector<valtype>&, bool raw = false);
int print_bool_stack(std::vector<valtype>&);

void print_dualstack();

#endif // included_btcdeb_functions_h_
