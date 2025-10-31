// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <getopt.h>
#include <shadow.h>
#include <stdbool.h>

#include "basics.h"
#include "pwaccess.h"

#define DAY (24L*3600L)
#define SCALE DAY

/* Print the time in a human readable format.  */
static void
print_date(time_t date)
{
  struct tm *tp;
  char buf[40];

  tp = gmtime(&date);
  if (strftime(buf, sizeof buf, "%b %d, %Y", tp) == 0)
    {
      puts("strftime failed!");
      return;
    }
  puts(buf);
}


/* Print the current values of the expiration fields.  */
static int
print_shadow_info (const char *user)
{
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  _cleanup_free_ char *error = NULL;
  bool complete = false;
  int r;

  r = pwaccess_get_user_record(user?-1:(int64_t)getuid(), user?user:NULL,
			       &pw, &sp, &complete, &error);
  if (r < 0)
    {
      fprintf(stderr, "get_user_record failed: %s\n", error?error:strerror(-r));
      return -r;
    }

  if (pw == NULL)
    {
      fprintf(stderr, "ERROR: Unknown user '%s'.\n", user);
      return ENOENT;
    }
  if (sp == NULL)
    {
      fprintf(stderr, "ERROR: No shadow entry for user '%s' found.\n", user);
      return ENOENT;
    }
  if (!complete)
    {
      fprintf(stderr, "Permission denied.\n");
      return EPERM;
    }

  printf ("Last password change:\t\t");
  if (sp->sp_lstchg == 0)
    printf("password change enforced\n");
  else if (sp->sp_lstchg < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE);

  printf("Password expires:\t\t");
  if (sp->sp_lstchg < 0 || sp->sp_max >= 10000 * (DAY / SCALE)
      || sp->sp_max < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE + sp->sp_max * SCALE);

  printf("Password inactive:\t\t");
  if (sp->sp_lstchg < 0 || sp->sp_inact < 0 ||
      sp->sp_max >= 10000 * (DAY / SCALE) || sp->sp_max < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE +
               (sp->sp_max + sp->sp_inact) * SCALE);

  printf("Account expires:\t\t");
  if (sp->sp_expire < 0)
    printf("never\n");
  else
    print_date(sp->sp_expire * SCALE);

  printf("Minimum password age:\t\t");
  if (sp->sp_min <= 0)
    printf("disabled\n");
  else
    printf("%ld days\n", sp->sp_min);
  printf("Maximum password age:\t\t");
  if (sp->sp_max <= 0)
    printf("disabled\n");
  else
    printf("%ld days\n", sp->sp_max);
  printf("Password warning period:\t");
  if (sp->sp_warn <= 0)
    printf("disabled\n");
  else
    printf("%ld days\n", sp->sp_warn);
  printf("Password inactivity period:\t");
  if (sp->sp_inact < 0)
    printf("disabled\n");
  else
    printf("%ld days\n", sp->sp_inact);

  return 0;
}

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: chage [options] [--help] [--version] [user]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "chage - change and list user expiry data\n\n");
  print_usage(stdout);

  fputs("  -l, --list     List account aging information\n", stdout);
  fputs("  -h, --help     Give this help list\n", stdout);
  fputs("  -v, --version  Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf(stderr, "Try `chage --help' for more information.\n");
}

int
main(int argc, char **argv)
{
  int l_flag = 0;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"list",        no_argument,       NULL, 'l' },
          {"version",     no_argument,       NULL, 'v' },
          {"help",        no_argument,       NULL, 'h' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long(argc, argv, "lvh",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'l':
          l_flag = 1;
          break;
        case 'h':
          print_help();
          return 0;
        case 'v':
	  printf("chage (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_error();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf(stderr, "chage: Too many arguments.\n");
      print_error();
      return EINVAL;
    }

  if (l_flag)
    return print_shadow_info(argv[0]);
  else
    {
      print_usage(stderr);
      return EINVAL;
    }

  return 0;
}
