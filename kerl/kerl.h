/* This is improved by using the ax_lib_readline.m4 macro with automake.
   To compile directly use -DNO_AUTOMAKE in call to gcc. */

#ifndef included_kerl_h_
#define included_kerl_h_

#ifdef HAVE_CONFIG_H
// TODO: fix this weird dependency
#  include <config/bitcoin-config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef NO_AUTOMAKE
#  include <readline/readline.h>
#  include <readline/history.h>
#  define HAVE_LIBREADLINE
#  define HAVE_READLINE_HISTORY
#else
#  ifdef HAVE_LIBREADLINE
#    if defined(HAVE_READLINE_READLINE_H)
#      include <readline/readline.h>
#    elif defined(HAVE_READLINE_H)
#      include <readline.h>
#    else /* !defined(HAVE_READLINE_H) */
       char *readline ();
#    endif /* !defined(HAVE_READLINE_H) */
     extern char *cmdline;
#  else /* !defined(HAVE_READLINE_READLINE_H) */
     /* no readline */
#  endif /* HAVE_LIBREADLINE */

#  ifdef HAVE_READLINE_HISTORY
#    if defined(HAVE_READLINE_HISTORY_H)
#      include <readline/history.h>
#    elif defined(HAVE_HISTORY_H)
#      include <history.h>
#    else /* !defined(HAVE_HISTORY_H) */
       extern void add_history ();
       extern int write_history ();
       extern int read_history ();
#    endif /* defined(HAVE_READLINE_HISTORY_H) */
     /* no history */
#  endif /* HAVE_READLINE_HISTORY */
#endif

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

#endif // included_kerl_h_
