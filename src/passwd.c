// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <pwd.h>
#include <getopt.h>
#include <shadow.h>
#include <stdbool.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>

#include "basics.h"
#include "pwaccess.h"
#include "varlink-client-common.h"

#define USEC_INFINITY ((uint64_t) UINT64_MAX)

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: passwd [--help] [--usage] [--version] [user]\n");
}

static void
print_help(void)
{
  print_usage(stdout);
  fprintf(stdout, "passwd - change user password\n\n");

  fputs("      --help     Give this help list\n", stdout);
  fputs("  -u, --usage    Give a short usage message\n", stdout);
  fputs("  -v, --version  Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `passwd --help' or `passwd --usage' for more information.\n");
}


int
main(int argc _unused_, char **argv _unused_)
{
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"version",     no_argument,       NULL, 'v' },
          {"usage",       no_argument,       NULL, 'u' },
          {"help",        no_argument,       NULL, '\255' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "vu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case '\255':
          print_help();
          return 0;
        case 'v':
          // XXX print_version(program, "2005");
          return 0;
        case 'u':
          print_usage(stdout);
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
      fprintf(stderr, "passwd: Too many arguments.\n");
      print_error();
      return EINVAL;
    }
  else
    {
      _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
      _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
      const char *user = NULL;
      int r;

      if (argc == 1)
        user = argv[0];
      else
        {
          struct passwd *pw = getpwuid(getuid());
          if (pw == NULL)
            {
              fprintf(stderr, "User (%u) not found!\n", getuid());
              return ENOENT;
            }
          user = strdupa(pw->pw_name);
          if (user == NULL)
            {
              fprintf(stderr, "Out of memory!\n");
              return ENOMEM;
            }
        }

      r = connect_to_pwupdd(&link, _VARLINK_PWUPD_SOCKET, NULL /* XXX error */);
      if (r < 0)
	return -r;

      r = sd_json_buildo(&params,
			 SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user)));
      if (r < 0)
	{
	  fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
	  return -r;
	}

      r = sd_varlink_bind_reply(link, reply_callback);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to bind reply callback: %s\n", strerror(-r));
	  return -r;
	}

      r = sd_varlink_observe(link, "org.openSUSE.pwupd.Chauthtok", params);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to call chauthtok method: %s\n", strerror(-r));
	  return -r;
	}

    loop:
      for (;;)
	{
	  r = sd_varlink_is_idle(link);
	  if (r < 0)
	    {
	      fprintf(stderr, "Failed to check if varlink connection is idle: %s\n", strerror(-r));
	      return -r;
	    }
	  if (r > 0)
	    break;

	  r = sd_varlink_process(link);
	  if (r < 0)
	    {
	      fprintf(stderr, "Failed to process varlink connection: %s\n", strerror(-r));
	      return -r;
	    }
	  if (r != 0)
	    continue;

	  r = sd_varlink_wait(link, USEC_INFINITY);
	  if (r < 0)
	    {
	      fprintf(stderr, "Failed to wait for varlink connection events: %s\n", strerror(-r));
	      return -r;
	    }
	}

      if (resp)
	{
	  _cleanup_(sd_json_variant_unrefp) sd_json_variant *answer = NULL;

	  r = sd_json_buildo(&answer,
			     SD_JSON_BUILD_PAIR("response", SD_JSON_BUILD_STRING(resp->resp)));
	  if (r < 0)
	    {
	      fprintf(stderr, "Failed to build response list: %s\n", strerror(-r));
	      return -r;
	    }

	  free(resp->resp);
	  resp = mfree(resp);

	  sd_json_variant_sensitive(answer); /* password is sensitive */

	  r = sd_varlink_observe(link, "org.openSUSE.pwupd.Conv", answer);
	  if (r < 0)
	    {
	      fprintf(stderr, "Failed to call conv method: %s\n", strerror(-r));
	      return -r;
	    }
	  goto loop;
	}
    }

  return 0;
}
