
#define _GNU_SOURCE 1

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <stdbool.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: dump-privs [options]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "dump-privs - dump process privileges\n\n");

  print_usage(stdout);

  fputs("  -e, --enivronment      Print enviornment variables\n", stdout);
  fputs("  -w, --wait             Wait for <enter> before exit\n", stdout);
  fputs("  -h, --help             Give this help list\n", stdout);
  fputs("  -v, --version          Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `dump-privs --help' for more information.\n");
}

/* conpare function for qsort */
static int
compare_str(const void *a, const void *b)
{
  return strcmp(*(const char **)a, *(const char **)b);
}

static int
agetgroups(int *ngids, gid_t **res)
{
  gid_t *gids;
  int n;

  *ngids = 0;
  *res = NULL;

  n = getgroups(0, NULL);
  if (n == -1)
    return -errno;

  gids = calloc(n, sizeof(gid_t));
  if (gids == NULL)
    return -ENOMEM;

  n = getgroups(n, gids);
  if (n == -1)
    {
      int r = errno;

      free(gids);
      return -r;
    }

  *ngids = n;
  *res = gids;
  return 0;
}

static const char *
selinux_status(void)
{
#ifdef WITH_SELINUX
  if (is_selinux_enabled() > 0)
    {
      int r = security_getenforce();
      switch (r)
        {
        case 1:
          return "enforcing";
          break;
        case 0:
          return "permissive";
          break;
        default:
          fprintf(stderr, "selinux error: %s\n",
		  strerror(errno));
          return "error";
          break;
        }
    }
  else
    return "off";
#else
  return "not available";
#endif
}

int
main(int argc, char **argv)
{
  bool wait = false;
  bool printenv = false;
  int ngids = 0;
  gid_t *gids = NULL;
  char *secon = NULL;
  char *cwd = NULL;
  int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  const char *sestatus = selinux_status();
  int r;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"environment", no_argument,       NULL, 'e' },
          {"help",        no_argument,       NULL, 'h' },
          {"version",     no_argument,       NULL, 'v' },
          {"wait",        no_argument,       NULL, 'w' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "ehvw",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'e':
	  printenv = true;
	  break;
        case 'h':
          print_help();
          return 0;
        case 'v':
          printf("dump-privs (%s) %s\n", PACKAGE, VERSION);
          return 0;
        case 'w':
	  wait = true;
          break;
        default:
          print_error();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    {
      fprintf(stderr, "dump-privs: Too many arguments.\n");
      print_error();
      return EINVAL;
    }

  r = agetgroups(&ngids, &gids);
  if (r != 0)
    fprintf(stderr, "getgroups() failed: %s\n", strerror(-r));

  printf("🔎 Process Security Information\n");
  printf("-------------------------------\n");
  printf("Real UID:          %d\n", getuid());
  printf("Effective UID:     %d\n", geteuid());
  printf("Real GID:          %d\n", getgid());
  printf("Effective GID:     %d\n", getegid());
  printf("Group memberships:");
  for (int i = 0; i < ngids; i++)
    {
      if (i != 0)
	putchar(',');
      printf(" %jd", (intmax_t) gids[i]);
    }
  putchar('\n');
  printf("SELinux Status:    %s\n", sestatus);
  if (getcon(&secon) == 0)
    {
      printf("SELinux Context:   %s\n",   secon);
      freecon(secon); /* Free the memory allocated by getcon() */
    }
  else
    fprintf(stderr, "SELinux Context:   %s\n", strerror(errno));
  printf("NoNewPrivs Status: %s\n", no_new_privs==0?"off":"on");

  cwd = get_current_dir_name();
  if (cwd == NULL)
    fprintf(stderr, "Current directory: %s\n", strerror(errno));
  else
    {
      printf("Current directory: %s\n", cwd);
      free(cwd);
    }

  if (printenv)
    {
      int count = 0;
      char **envp = environ;
      while (*envp != NULL)
	{
	  count++;
	  envp++;
	}
      qsort(environ, count, sizeof(char *), compare_str);
      envp = environ;
      fputs("Environement variables:\n", stdout);
      while (*envp != NULL)
	{
	  printf("%s\n", *envp);
	  envp++;
	}
    }

  if (wait)
    getchar();

  return 0;
}
