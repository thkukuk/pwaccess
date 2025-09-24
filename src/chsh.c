// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <pwd.h>
#include <getopt.h>
#include <shadow.h>
#include <stdbool.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>
#include <security/pam_misc.h>
#include <libeconf.h>

#include "basics.h"
#include "pwaccess.h"
#include "varlink-client-common.h"

#define USEC_INFINITY ((uint64_t) UINT64_MAX)

static int
get_shell_list(void)
{
  _cleanup_(econf_freeFilep) econf_file *key_file = NULL;
  _cleanup_(econf_freeArrayp) char **keys = NULL;
  size_t size = 0;
  econf_err error;

  error = econf_readConfig(&key_file,
			   NULL /* project */,
			   "/usr/etc" /* usr_conf_dir */,
			   "shells" /* config_name */,
			   NULL /* config_suffix */,
			   "" /* delim, key only */,
			   "#" /* comment */);
  if (error != ECONF_SUCCESS)
    {
      fprintf(stderr, "Cannot parse shell files: %s",
	      econf_errString(error));
      return 1;
    }

  error = econf_getKeys(key_file, NULL, &size, &keys);
  if (error)
    {
      fprintf(stderr, "Cannot evaluate entries in shell files: %s",
	      econf_errString(error));
      return 1;
    }

  for (size_t i = 0; i < size; i++)
    printf("%s\n", keys[i]);

  return 0;
}

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: chsh [-s shell] [-l] [--help] [--usage] [--version] [user]\n");
}

static void
print_help(void)
{
  print_usage(stdout);
  fprintf(stdout, "chsh - change login shell\n\n");

  fputs("  -l             List allowed shells from /etc/shells\n", stdout);
  fputs("  -s shell       Use 'shell' as new login shell\n", stdout);
  fputs("      --help     Give this help list\n", stdout);
  fputs("  -u, --usage    Give a short usage message\n", stdout);
  fputs("  -v, --version  Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `chsh --help' or `chsh --usage' for more information.\n");
}

int
main(int argc, char **argv)
{
  char *new_shell = NULL;
  int l_flag = 0;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"shell",       required_argument, NULL, 's' },
          {"list-shells", no_argument,       NULL, 'l' },
          {"version",     no_argument,       NULL, 'v' },
          {"usage",       no_argument,       NULL, 'u' },
          {"help",        no_argument,       NULL, '\255' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "s:lvu",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'l':
          l_flag = 1;
          break;
        case 's':
          if (!optarg)
            {
              print_usage(stderr);
              return 1;
            }
          new_shell = optarg;
          break;
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

  if (argc > 1 || (l_flag && argc > 0))
    {
      fprintf(stderr, "chsh: Too many arguments.\n");
      print_error();
      return 1;
    }

  if (l_flag && new_shell)
    {
      fprintf(stderr, "chsh: Too many arguments.\n");
      print_error();
      return 1;
    }
  if (l_flag)
    {
      return get_shell_list();
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

      /* XXX if new_shell == NULL, ask for shell */

      r = connect_to_pwupdd(&link, _VARLINK_PWUPD_SOCKET, NULL /* XXX error */);
      if (r < 0)
	return r;

      r = sd_json_buildo(&params,
			 SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user)),
			 SD_JSON_BUILD_PAIR("shell", SD_JSON_BUILD_STRING(strempty(new_shell))));
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

      r = sd_varlink_observe(link, "org.openSUSE.pwupd.Chsh", params);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to call chsh method: %s\n", strerror(-r));
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
	      return r;
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
			     SD_JSON_BUILD_PAIR("response", SD_JSON_BUILD_STRING(strempty(resp->resp))));
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
      return -r;
    }

  return 0;
}
