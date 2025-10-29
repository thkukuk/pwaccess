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
#include "get_value.h"
#include "chfn_checks.h"

#define USEC_INFINITY ((uint64_t) UINT64_MAX)

static int
ask_or_print(const char *old, const char *prompt, char **input, char field)
{
  _cleanup_free_ char *error = NULL;
  bool allowed = true;
  int r;

  allowed = may_change_field(getuid(), field, &error);
  if (error)
    {
      fprintf(stderr, "%s\n", error);
      return -EPERM;
    }
  if (allowed)
    {
      r = get_value(old, prompt, input);
      if (r < 0)
	return r;

      if (*input == NULL)
	{
	  fprintf(stderr, "chfn aborted.\n");
	  return -ENODATA;
	}

      /* don't change string if equal */
      if (streq(strempty(old), *input))
	*input = mfree(*input);
      else
	{
	  /* field "other" allows ',' and '=' */
	  if (!chfn_check_string(*input, field=='o'?":":":,=", &error))
	    {
	      *input = mfree(*input);
	      if (error)
		fprintf(stderr, "%s: %s\n", prompt, error);
	      return -EINVAL;
	    }
	}
    }
  else
    printf("%s: '%s'\n", prompt, strempty(old));

  return 0;
}

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: chfn [options] [user]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "chfn - change user information\n\n");
  print_usage(stdout);

  fputs("  -f, --full-name <name>   Change full name\n", stdout);
  fputs("  -h, --home-phone <phone> Change home phone number\n", stdout);
  fputs("  -o, --other <other>      Change other GECOS information\n", stdout);
  fputs("  -r, --room <number>      Change room number\n", stdout);
  fputs("  -w, --work-phone <phone> Change work phone number\n", stdout);
  fputs("  -u, --help               Give this help list\n", stdout);
  fputs("  -v, --version            Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `chfn --help' for more information.\n");
}

int
main(int argc, char **argv)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_free_ char *new_full_name = NULL;
  _cleanup_free_ char *new_home_phone = NULL;
  _cleanup_free_ char *new_other = NULL;
  _cleanup_free_ char *new_room = NULL;
  _cleanup_free_ char *new_work_phone = NULL;
  const char *old_full_name = NULL;
  const char *old_home_phone = NULL;
  const char *old_other = NULL;
  const char *old_room = NULL;
  const char *old_work_phone = NULL;
  const char *user = NULL;
  int r;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"full-name",   required_argument, NULL, 'f' },
	  {"home-phone",  required_argument, NULL, 'h' },
	  {"other",       required_argument, NULL, 'o' },
	  {"room",        required_argument, NULL, 'r' },
	  {"work-phone",  required_argument, NULL, 'w' },
          {"version",     no_argument,       NULL, 'v' },
          {"help",        no_argument,       NULL, 'u' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "f:h:o:r:uvw:",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'f':
          new_full_name = strdup(optarg);
	  if (new_full_name == NULL)
	    return ENOMEM;
          break;
	case 'h':
	  new_home_phone = strdup(optarg);
	  if (new_home_phone == NULL)
	    return ENOMEM;
	  break;
	case 'o':
	  new_other = strdup(optarg);
	  if (new_other == NULL)
	    return ENOMEM;
	  break;
	case 'r':
	  new_room = strdup(optarg);
	  if (new_room == NULL)
	    return ENOMEM;
	  break;
	case 'w':
	  new_work_phone = strdup(optarg);
	  if (new_work_phone == NULL)
	    return ENOMEM;
	  break;
        case 'u':
          print_help();
          return 0;
        case 'v':
	  printf("chfn (%s) %s\n", PACKAGE, VERSION);
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
      fprintf(stderr, "chfn: Too many arguments.\n");
      print_error();
      return 1;
    }

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

  /* no new values as argument provided, ask for them */
  if (!new_full_name && !new_home_phone && !new_other &&
      !new_room && !new_work_phone)
    {
      char *p;
      const char *f;
      struct passwd *pw = getpwnam(user);
      if (pw == NULL)
	{
	  fprintf(stderr, "User (%s) not found!\n", user);
	  return ENOENT;
	}

      /* set old values */
      p = pw->pw_gecos;
      f = strsep(&p, ",");
      old_full_name = f;
      f = strsep(&p, ",");
      old_room = f;
      f = strsep(&p, ",");
      old_work_phone = f;
      f = strsep(&p, ",");
      old_home_phone = f;
      /* Anything left over is "other".  */
      old_other = p;

      printf("Enter the new value, or press return for the default.\n");

      r = ask_or_print(old_full_name, "Full Name", &new_full_name, 'f');
      if (r < 0)
	return -r;

      r = ask_or_print(old_room, "Room Number", &new_room, 'r');
      if (r < 0)
	return -r;

      r = ask_or_print(old_work_phone, "Work Phone", &new_work_phone, 'w');
      if (r < 0)
	return -r;

      r = ask_or_print(old_home_phone, "Home Phone", &new_home_phone, 'h');
      if (r < 0)
	return -r;

      r = ask_or_print(old_other, "Other", &new_other, 'o');
      if (r < 0)
	return -r;
    }

  /* abort if there is nothing to change */
  if (!new_full_name && !new_home_phone && !new_other &&
      !new_room && !new_work_phone)
    {
      printf("Nothing to change.\n");
      return 0;
    }

  r = connect_to_pwupdd(&link, _VARLINK_PWUPD_SOCKET, NULL /* XXX error */);
  if (r < 0)
    return -r;

  r = sd_json_variant_merge_objectbo(&params,
				     SD_JSON_BUILD_PAIR_STRING("userName", user));
  if (r >= 0 && new_full_name)
    r = sd_json_variant_merge_objectbo(&params,
				       SD_JSON_BUILD_PAIR_STRING("fullName", new_full_name));
  if (r >= 0 && new_room)
    r = sd_json_variant_merge_objectbo(&params,
				       SD_JSON_BUILD_PAIR_STRING("room", new_room));
  if (r >= 0 && new_work_phone)
    r = sd_json_variant_merge_objectbo(&params,
				       SD_JSON_BUILD_PAIR_STRING("workPhone", new_full_name));
  if (r >= 0 && new_home_phone)
    r = sd_json_variant_merge_objectbo(&params,
				       SD_JSON_BUILD_PAIR_STRING("homePhone", new_full_name));
  if (r >= 0 && new_other)
    r = sd_json_variant_merge_objectbo(&params,
				       SD_JSON_BUILD_PAIR_STRING("other", new_other));
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

  r = sd_varlink_observe(link, "org.openSUSE.pwupd.Chfn", params);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call chfn method: %s\n", strerror(-r));
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

  return 0;
}
