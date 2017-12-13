#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>
#include <readline/history.h>

typedef int (*kerl_bindable) (const char *arg);
typedef char *(*kerl_completor)(const char *text, int continued);

void kerl_register(const char *name, kerl_bindable func, const char *doc);
void kerl_register_help(const char *name);
void kerl_set_completor(const char *name, kerl_completor completor);
void kerl_run(const char *prompt);
void kerl_set_history_file(const char *path);
void kerl_set_repeat_on_empty(int flag);
int kerl_make_argcv(const char *argstring, size_t *argcOut, char ***argvOut);
int kerl_make_argcv_escape(const char *argstring, size_t *argcOut, char ***argvOut, char escape);
void kerl_free_argcv(size_t argc, char **argv);
