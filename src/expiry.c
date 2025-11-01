// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <security/pam_appl.h>

#include "basics.h"
#include "pwaccess.h"
#include "chauthtok.h"

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: expiry [-c|-f] [user] [--help] [--version]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "expiry - check password expiration and force password change\n\n");
  print_usage(stdout);

  fputs("  -c, --check         Print number of days when password expires\n", stdout);
  fputs("  -f, --force         Force password change if password is expired\n", stdout);
  fputs("  -h, --help          Give this help list\n", stdout);
  fputs("  -v, --version       Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `expiry --help' for more information.\n");
}

int
main(int argc, char **argv)
{
  _cleanup_free_ char *error = NULL;
  _cleanup_free_ char *user = NULL;
  long daysleft = -1;
  int cflg = 0;
  int fflg = 0;
  int r;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"check",   no_argument, NULL, 'c' },
          {"force",   no_argument, NULL, 'f' },
          {"help",    no_argument, NULL, 'h' },
          {"version", no_argument, NULL, 'v' },
          {NULL,      0,           NULL, '\0'}
        };

      c = getopt_long (argc, argv, "cfhv",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'c':
          cflg = 1;
          break;
        case 'f':
	  fflg = 1;
          break;
        case 'h':
          print_help();
          return 0;
        case 'v':
	  printf("expiry (%s) %s\n", PACKAGE, VERSION);
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
      fprintf(stderr, "expiry: too many arguments.\n");
      print_error();
      return EINVAL;
    }
  if (cflg+fflg > 1)
    {
      fprintf(stderr, "expiry: options -c and -f conflict.\n");
      print_error();
      return EINVAL;
    }

  /* common for -c and -f */
  if (argc == 1)
    {
      user = strdup(argv[0]);
      if (!user)
	{
	  fprintf(stderr, "Out of memory!\n");
	  return ENOMEM;
	}
    }
  else
    {
      r = pwaccess_get_account_name(getuid(), &user, &error);
      if (r < 0)
	{
	  fprintf(stderr, "Get account name failed: %s\n",
		  error?error:strerror(-r));
	  return -r;
	}
    }

  r = pwaccess_check_expired(user, &daysleft,
			     NULL /* pwchangeable */, &error);
  if (r < 0)
    {
      fprintf(stderr, "Calling pwaccess check expired failed: %s\n",
	      error?error:strerror(-r));
      return -r;
    }

  if (cflg)
    {
      if (daysleft >= 0)
        printf("Your password will expire in %ld %s.\n",
	       daysleft, (daysleft == 1)?"day":"days");

      /* return expire status as return value */
      return r;
    }
  else if (fflg)
    {
      switch (r)
	{
	case PWA_EXPIRED_NO:
	  return 0;
	  break;
	case PWA_EXPIRED_ACCT:
	  printf("Your account has expired; please contact your system administrator.\n");
	  return EPERM;
	  break;
	case PWA_EXPIRED_CHANGE_PW:
	  printf("Your password has expired.\n");
	  break;
	case PWA_EXPIRED_PW:
	  printf("Your password is inactive; please contact your system administrator.\n");
	  return EPERM;
	  break;
	default:
	  fprintf(stderr, "Unexpected expire value: %i\n", r);
	  return EINVAL;
	  break;
	}
      return chauthtok(user, PAM_CHANGE_EXPIRED_AUTHTOK);
    }
  else
    {
      fprintf(stderr, "expiry: no arguments provided.\n");
      print_error();
      return 1;
    }

  return 0;
}
