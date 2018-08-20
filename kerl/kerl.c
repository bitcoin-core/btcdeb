/* Based on ... */
/* fileman.c -- A tiny application which demonstrates how to use the
   GNU Readline library.  This application interactively allows users
   to manipulate files and their modes. */

#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "kerl.h"

#ifndef NO_AUTOMAKE
#  ifdef HAVE_LIBREADLINE
char *cmdline = NULL;
#  endif
#endif

#ifndef whitespace
#define whitespace(c) (((c) == ' ') || ((c) == '\t'))
#endif

int kerl_com_help();
char *command_generator ();

/* A structure which contains information on the commands this program
   can understand. */

typedef struct {
  char *name;          /* User printable name of the function. */
  kerl_bindable func;  /* Function to call to do the job. */
  char *doc;           /* Documentation for this function.  */
  kerl_completor compl;/* Completion engine, or NULL if none. */
} COMMAND;

int command_count = 0;
int command_cap = 0;
int repeat_empty;      /* Blank lines are interpreted as "repeat previous command". */
char comment_char = 0;
COMMAND *commands = NULL;
int execute_line(char *line);
char *history_file = NULL;
kerl_bindable fallback = NULL;

/* sensitivity */
int skip_history = 0;
int may_skip_history = 0;
int whitespace_to_skip_history = 0;

void kerl_set_sensitive(int do_not_store_history) {
    skip_history = do_not_store_history;
}

void kerl_set_enable_sensitivity() {
    may_skip_history = 1;
}

void kerl_set_enable_whitespaced_sensitivity() {
    kerl_set_enable_sensitivity();
    whitespace_to_skip_history = 1;
}

/* Forward declarations. */
char *stripwhite ();
COMMAND *find_command ();
void initialize_readline ();
void kerl_add_history(const char *line);

void kerl_register(const char *name, kerl_bindable func, const char *doc)
{
  if (command_cap == 0) {
    command_cap = 8;
    commands = malloc(sizeof(COMMAND) * command_cap);
  } else if (command_cap == command_count) {
    command_cap *= 2;
    commands = realloc(commands, sizeof(COMMAND) * command_cap);
  }
  commands[command_count++] = (COMMAND) {strdup(name), func, strdup(doc), NULL};
}

void kerl_register_fallback(kerl_bindable func)
{
  fallback = func;
}

void kerl_set_completor(const char *name, kerl_completor completor)
{
  COMMAND *cmd = find_command(name);
  assert(cmd);
  cmd->compl = completor;
}

void kerl_set_repeat_on_empty(int flag)
{
  repeat_empty = flag;
}

void kerl_set_comment_char(char commentchar)
{
    comment_char = commentchar;
}

void kerl_register_help(const char *name)
{
  kerl_register(name, kerl_com_help, "Show help information.");
  kerl_set_completor(name, command_generator);
}

/* When non-zero, this global means the user is done using this program. */
int done;

char *dupstr (char *s)
{
  char *r;

  r = malloc(strlen(s) + 1);
  strcpy(r, s);
  return r;
}

#ifndef HAVE_LIBREADLINE
char* readline(const char* prompt) {
  static char buf[10240];
  fputs(prompt, stdout);
  char* pbuf = fgets(buf, 10240, stdin);
  if (!pbuf) return NULL;
  size_t len = strlen(buf);
  while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = 0;
  return pbuf ? strdup(buf) : NULL;
}
#endif

void kerl_run(const char *prompt)
{
  char *line, *pline = NULL, *s, *p = NULL, *sensitive_s;

  initialize_readline (); /* Bind our completer. */

  /* Loop reading and executing lines until the user quits. */
  for ( ; done == 0; ) {
    line = readline(prompt);
    if (line && comment_char) {
        // consume until we run into comment_char then term
        for (char* p = line; *p; ++p) {
            if (*p == comment_char) {
                *p = 0;
                break;
            }
        }
    }

    if (!line) break;

    /* Remove leading and trailing whitespace from the line.
       Then, if there is anything left, add it to the history list
       and execute it. */
    s = stripwhite(line);
    if (s > line && whitespace_to_skip_history) skip_history = 1;

    if (*s) {
      if (repeat_empty) {
        if (pline) free(pline);
        pline = strdup(line);
        p = stripwhite(pline);
      }
      if (may_skip_history) {
          sensitive_s = strdup(s);
          execute_line(s);
          if (!skip_history) {
              kerl_add_history(sensitive_s);
          }
          skip_history = 0;
          free(sensitive_s);
      } else {
          kerl_add_history(s);
          execute_line(s);
      }
    } else if (repeat_empty) {
      if (p) {
          s = strdup(p);
          execute_line(s);
          free(s);
      }
    }
    free(line);
  }
}

void kerl_add_history(const char *s)
{
#ifdef HAVE_READLINE_HISTORY
  add_history(s);
#endif // HAVE_READLINE_HISTORY
  if (history_file) {
    FILE *fp = fopen(history_file, "a");
    fprintf(fp, "%s\n", s);
    fclose(fp);
  }
}

void kerl_set_history_file(const char *path)
{
  if (history_file) free(history_file);
  history_file = strdup(path);
#ifdef HAVE_READLINE_HISTORY
  char buf[1024];
  FILE *file = fopen(path, "r");
  if (file) {
    while (NULL != (fgets(buf, 1024, file))) {
      buf[strlen(buf)-1] = 0; // get rid of \n
      add_history(buf);
    }
  }
#endif // HAVE_READLINE_HISTORY
}

/* Execute a command line. */
int execute_line(char *line)
{
  register int i;
  COMMAND *command;
  char *word;

  /* Isolate the command word. */
  i = 0;
  while (line[i] && whitespace (line[i]))
    i++;
  word = line + i;

  while (line[i] && !whitespace (line[i]))
    i++;

  if (line[i]) line[i++] = '\0';

  command = find_command(word);

  if (!command) {
    if (fallback) {
      if (i > 0 && !line[i-1]) line[i-1] = ' ';
      return fallback(line);
    }
    fprintf (stderr, "%s: No such command.\n", word);
    return (-1);
  }

  /* Get argument to command, if any. */
  while (whitespace(line[i]))
    i++;

  word = line + i;

  /* Call the function. */
  return command->func(word);
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
COMMAND *find_command(char *name)
{
  register int i;

  for (i = 0; i < command_count; i++) {
    if (strcmp(name, commands[i].name) == 0) {
      return &commands[i];
    }
  }

  return (COMMAND *)NULL;
}

char *strdup_command(char *line)
{
  register int i, x;
  x = strlen(line);
  for (i = 0; i < x && line[i] != ' '; i++);
  return strndup(line, i);
}

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *stripwhite(char *string)
{
  register char *s, *t;

  for (s = string; whitespace(*s); s++);
  
  if (*s == 0)
    return s;

  t = s + strlen(s) - 1;
  while (t > s && whitespace(*t))
    t--;
  *++t = '\0';

  return s;
}

int kerl_com_help(const char *arg)
{
  register int i;
  int arglen = arg ? strlen(arg) : 0;

  int max_clen = 0, clen;
  for (i = 0; i < command_count; i++) {
    if (!arglen || !strncmp(commands[i].name, arg, arglen)) {
      clen = strlen(commands[i].name);
      if (clen > max_clen) max_clen = clen;
    }
  }
  int found = 0;
  char fmt[16];
  sprintf(fmt, "%%-%ds %%s\n", max_clen);
  for (i = 0; i < command_count; i++) {
    if (!arglen || !strncmp(commands[i].name, arg, arglen)) {
      printf(fmt, commands[i].name, commands[i].doc);
      found++;
    }
  }
  if (found == 0) {
    fprintf(stderr, "%s: no command with this prefix\n", arg);
  }
  return found > 0;
}

int kerl_make_argcv(const char *argstring, size_t *argcOut, char ***argvOut)
{
  return kerl_make_argcv_escape(argstring, argcOut, argvOut, 0);
}

int kerl_make_argcv_escape(const char *argstring, size_t *argcOut, char ***argvOut, char escape)
{
  register int i, j;
  size_t argc = 0, cap = 2;
  char **argv = malloc(sizeof(char*) * cap);
  char *line, ch, *buf, quot = 0, esc = 0;
  line = NULL;
  j = 0;
  size_t bufcap = 1024;
  buf = malloc(bufcap);
#define bufiter() { \
  if (ch == escape) buf[j++] = '\\'; \
  buf[j++] = ch; \
}
  while (1) {
    if (bufcap >= j - 2) { bufcap *= 2; buf = realloc(buf, bufcap); }
    for (i = 0; argstring[i]; i++) {
      ch = argstring[i];
      if (esc) { bufiter(); esc = 0; continue; }
      if (ch == '\\') esc = 1;
      else if (quot) {
        if (ch == quot) quot = 0;
        else bufiter(); //buf[j++] = ch;
      }
      else if (ch == '\'' || ch == '"') quot = ch;
      else if (ch == ' ') {
        if (j > 0) {
          if (argc == cap) {
            cap *= 2;
            argv = realloc(argv, sizeof(char*) * cap);
          }
          buf[j] = 0;
          argv[argc++] = strdup(buf);
          j = 0;
        }
      } else bufiter();
    }
    if (line) free(line);
#ifdef HAVE_LIBREADLINE
    if (quot || esc) {
      if (quot) buf[j++] = '\n';
      line = readline(quot == '"' ? "dquote> " : quot == '\'' ? "quote> " : "> ");
      if (!line) { printf("\n"); free(buf); *argcOut = 0; *argvOut = NULL; return -1; }
      argstring = line; // preserve whitespace as we are quoting
    } else break;
#else
    break;
#endif // HAVE_LIBREADLINE
  }

  if (j > 0) {
    if (argc == cap) {
      cap++;
      argv = realloc(argv, sizeof(char*) * cap);
    }
    buf[j] = 0;
    argv[argc++] = strdup(buf);
  }
  free(buf);

  *argcOut = argc;
  *argvOut = argv;

  return 0;
}

void kerl_free_argcv(size_t argc, char **argv)
{
  register size_t i;
  for (i = 0; i < argc; i++) free(argv[i]);
  free(argv);
}

int kerl_process_citation(const char* argstring, size_t* bytesOut, char** argsOut) {
    register int i, j = 0;
    char *line = NULL, ch, *buf, quot = 0;
    size_t bufcap = strlen(argstring) + 1;
    buf = malloc(bufcap);
    while (1) {
        if (bufcap >= j - 2) { bufcap *= 2; buf = realloc(buf, bufcap); }
        for (i = 0; argstring[i]; i++) {
            ch = argstring[i];
            if (quot) {
                if (ch == quot) quot = 0;
            } else if (ch == '\'' || ch == '"') {
                quot = ch;
            }
            buf[j++] = ch;
        }
        if (line) free(line);
#ifdef HAVE_LIBREADLINE
        if (quot) {
            buf[j++] = '\n';
            line = readline(quot == '"' ? "dquote> " : quot == '\'' ? "quote> " : "> ");
            if (!line) { printf("\n"); free(buf); *bytesOut = 0; *argsOut = NULL; return -1; }
            argstring = line; // preserve whitespace as we are quoting
        } else break;
#else
        break;
#endif // HAVE_LIBREADLINE
    }

    buf[j] = 0;
    *bytesOut = j;
    *argsOut = buf;

    return 0;
}

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */

char **kerl_completion ();

/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on filenames
   if not. */
void initialize_readline ()
{
#ifdef HAVE_LIBREADLINE
  /* Allow conditional parsing of the ~/.inputrc file. */
  rl_readline_name = "kerl";

  /* Tell the completer that we want a crack first. */
  rl_attempted_completion_function = kerl_completion;
#endif // HAVE_LIBREADLINE
}

/* Attempt to complete on the contents of TEXT.  START and END show the
   region of TEXT that contains the word to complete.  We can use the
   entire line in case we want to do some simple parsing.  Return the
   array of matches, or NULL if there aren't any. */
char **kerl_completion(char *text, int start, int end)
{
  char **matches;

  matches = (char **)NULL;
#ifdef HAVE_LIBREADLINE

  /* If this word is at the start of the line, then it is a command
     to complete. */
  if (start == 0) {
    matches = rl_completion_matches(text, command_generator);
  } else {
    /* If we have a custom completor, we use that. Otherwise it is the name 
       of a file in the current directory. */
    int spaces = 0;
    for (register int i = 0; spaces < 2 && i < rl_point; i++) spaces += rl_line_buffer[i] == ' ';
    if (spaces > 1) printf("spaces = %d in '%s', no completion for yoooou\n", spaces, rl_line_buffer);
    if (spaces < 2) {
      char *strcom = strdup_command(rl_line_buffer);
      COMMAND *com = find_command(strcom);
      if (com && com->compl) {
        matches = rl_completion_matches(text, com->compl);
        } else {
            printf("no completion for command %s\n", strcom);
        }
        free(strcom);
    }
  }
#endif // HAVE_LIBREADLINE
  return matches;
}

/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
char *command_generator (const char *text, int state)
{
  static int list_index, len;
  char *name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */
  if (!state) {
    list_index = -1;
    len = strlen(text);
  }

  /* Return the next name which partially matches from the command list. */
  while (++list_index < command_count) {
    name = commands[list_index].name;

    if (strncmp(name, text, len) == 0)
      return (dupstr(name));
  }

  /* If no names matched, then return NULL. */
  return (char *)NULL;
}
