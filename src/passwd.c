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
#include "verify.h"
#include "chauthtok.h"

#define ARG_DELETE_PASSWORD  1
#define ARG_EXPIRE           2
#define ARG_LOCK_PASSWORD    4
#define ARG_UNLOCK_PASSWORD  8
#define ARG_STATUS_ACCOUNT  16

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: passwd [options] [user]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "passwd - change user password\n\n");

  print_usage(stdout);

  fputs("  -d, --delete      Delete password\n", stdout);
  fputs("  -e, --expire      Immediately expire password\n", stdout);
  fputs("  -h, --help        Give this help list\n", stdout);
  fputs("  -k, --keep-tokens Change only expired passwords\n", stdout);
  fputs("  -l, --lock        Lock password\n", stdout);
  fputs("  -q, --quiet       Be silent\n", stdout);
  fputs("  -S, --status      Display account status\n", stdout);
  fputs("  -u, --unlock      Unlock password\n", stdout);
  fputs("  -v, --version     Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `passwd --help' for more information.\n");
}

#define DAY (24L*3600L)
#define SCALE DAY

/* XXX don't use static char buf */
static inline char *
date2str(time_t date)
{
  static char buf[12];
  struct tm tm;

  if (date < 0)
    strcpy(buf, "never");
 else if (!gmtime_r(&date, &tm))
   strcpy(buf, "future");
 else
   strftime (buf, sizeof (buf), "%Y-%m-%d", &tm);

  return buf;
}

static const char *
pw_status(const char *pass)
{
  if (startswith(pass, "*") || startswith(pass, "!"))
    return "L";

  if (isempty(pass))
    return "NP";

  return "P";
}

static int
print_account_status(const char *user)
{
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *passwd = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *shadow = NULL;
  _cleanup_free_ char *error = NULL;
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  bool complete = false;
  int r;

  r = pwaccess_get_user_record(-1, user, &pw, &sp, &complete, &error);
  if (r < 0)
    {
      if (error)
        fprintf (stderr, "%s\n", error);
      else
        fprintf (stderr, "get_user_record failed: %s\n", strerror(-r));
      return -r;
    }

  if (pw == NULL)
    {
      fprintf(stderr, "ERROR: no password entry found!\n");
      return ENOENT;
    }

  if (!complete)
    {
      fprintf(stderr, "Error: couldn't read password field, ignoring.\n");
      return EPERM;
    }

  if (sp)
    printf("%s %s %s %ld %ld %ld %ld\n",
	   pw->pw_name,
	   pw_status (sp->sp_pwdp),
	   date2str(sp->sp_lstchg * SCALE),
	   sp->sp_min,
	   sp->sp_max,
	   sp->sp_warn,
	   sp->sp_inact);
  else if (pw->pw_passwd)
    printf("%s %s\n",
	   pw->pw_name, pw_status (pw->pw_passwd));
  else
    {
      fprintf(stderr, "Malformed password data obtained for user '%s'.\n",
	      pw->pw_name);
      return EINVAL;
    }
  return 0;
}

static int
modify_account(const char *user, int args, bool quiet)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *passwd = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *shadow = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
  _cleanup_free_ char *error = NULL;
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  bool complete = false;
  // XXX _cleanup_(struct_result_free) struct result p = {
  struct result p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct result, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct result, error), 0 },
    {}
  };
  int r;

  r = pwaccess_get_user_record(-1, user, &pw, &sp, &complete, &error);
  if (r < 0)
    {
      if (error)
        fprintf (stderr, "%s\n", error);
      else
        fprintf (stderr, "get_user_record failed: %s\n", strerror(-r));
      return -r;
    }

  if (pw == NULL)
    {
      fprintf(stderr, "ERROR: no password entry found!\n");
      return ENOENT;
    }

  if (!complete)
    printf("Warning: couldn't read password field, ignoring.\n");

  int has_change = 0;

  if (args & ARG_DELETE_PASSWORD)
    {
      if (pw->pw_passwd)
	pw->pw_passwd = mfree(pw->pw_passwd);

      pw->pw_passwd = strdup("");
      if (pw->pw_passwd == NULL)
	{
	  fprintf(stderr, "Out of memory!\n");
	  return ENOMEM;
	}

      if (sp)
	{
	  if (sp->sp_pwdp)
	    sp->sp_pwdp = mfree(sp->sp_pwdp);

	  sp->sp_pwdp = strdup("");
	  if (sp->sp_pwdp == NULL)
	    {
	      fprintf(stderr, "Out of memory!\n");
	      return ENOMEM;
	    }
	}
      has_change = 1;
    }
  if ((args & ARG_EXPIRE) && sp)
    {
      sp->sp_lstchg = 0;
      has_change = 1;
    }
  if (args & ARG_LOCK_PASSWORD)
    {
      char *newpw = NULL;

      if (is_shadow(pw))
	{
	  if (asprintf(&newpw, "!%s", strempty(sp->sp_pwdp)) < 0)
	    return ENOMEM;
	  free(sp->sp_pwdp);
	  sp->sp_pwdp = newpw;
	}
      else
	{
	  if (asprintf(&newpw, "!%s", strempty(pw->pw_passwd)) < 0)
	    return ENOMEM;
	  free(pw->pw_passwd);
	  pw->pw_passwd = newpw;
	}
      has_change = 1;
    }
  if (args & ARG_UNLOCK_PASSWORD)
    {
      char *newpw = NULL;

      if (is_shadow(pw) && startswith(sp->sp_pwdp, "!"))
	{
	  newpw=strdup(&(sp->sp_pwdp)[1]);
	  if (!newpw)
	    return ENOMEM;
	  free(sp->sp_pwdp);
	  sp->sp_pwdp = newpw;
	  has_change = 1;
	}
      else if (startswith(pw->pw_passwd, "!"))
	{
	  newpw=strdup(&(pw->pw_passwd)[1]);
	  if (!newpw)
	    return ENOMEM;
	  free(pw->pw_passwd);
	  pw->pw_passwd = newpw;
	  has_change = 1;
	}
    }
  if (!has_change)
    {
      if (!quiet)
	printf("Nothing to change.\n");
      return 0;
    }

  /* XXX unify opening socket */
  r = connect_to_pwupdd(&link, _VARLINK_PWUPD_SOCKET, &error);
  if (r < 0)
    {
      if (error)
	fprintf(stderr, "%s\n", error);
      else
	fprintf(stderr, "Cannot connect to pwupd! (%s)\n", strerror(-r));
      return -r;
    }

  r = sd_json_variant_merge_objectbo(&passwd,
                                     SD_JSON_BUILD_PAIR_STRING("name", pw->pw_name),
                                     SD_JSON_BUILD_PAIR_STRING("passwd", pw->pw_passwd),
                                     SD_JSON_BUILD_PAIR_INTEGER("UID", pw->pw_uid),
                                     SD_JSON_BUILD_PAIR_INTEGER("GID", pw->pw_gid),
                                     SD_JSON_BUILD_PAIR_STRING("GECOS", pw->pw_gecos),
                                     SD_JSON_BUILD_PAIR_STRING("dir", pw->pw_dir),
                                     SD_JSON_BUILD_PAIR_STRING("shell", pw->pw_shell));
  if (r < 0)
    {
      fprintf(stderr, "Error building passwd data: %s\n", strerror(-r));
      return -r;
    }

  if (sp)
    {
      r = sd_json_variant_merge_objectbo(&shadow,
                                         SD_JSON_BUILD_PAIR_STRING("name", sp->sp_namp),
                                         SD_JSON_BUILD_PAIR_STRING("passwd", sp->sp_pwdp),
                                         SD_JSON_BUILD_PAIR_INTEGER("lstchg", sp->sp_lstchg),
                                         SD_JSON_BUILD_PAIR_INTEGER("min", sp->sp_min),
                                         SD_JSON_BUILD_PAIR_INTEGER("max", sp->sp_max),
                                         SD_JSON_BUILD_PAIR_INTEGER("warn", sp->sp_warn),
                                         SD_JSON_BUILD_PAIR_INTEGER("inact", sp->sp_inact),
                                         SD_JSON_BUILD_PAIR_INTEGER("expire", sp->sp_expire),
                                         SD_JSON_BUILD_PAIR_INTEGER("flag", sp->sp_flag));
      if (r < 0)
        {
	  fprintf(stderr, "Error building shadow data: %s\n", strerror(-r));
	  return -r;
	}
    }

  r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_VARIANT("passwd", passwd));
  if (r >= 0 && shadow)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_VARIANT("shadow", shadow));
  if (r < 0)
    {
      fprintf(stderr, "JSON merge result object failed: %s", strerror(-r));
      return -r;
    }

  const char *error_id = NULL;
  r = sd_varlink_call(link, "org.openSUSE.pwupd.UpdatePasswdShadow", params, &result, &error_id);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call UpdatePasswdShadow method: %s\n", strerror(-r));
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      fprintf(stderr, "Failed to parse JSON answer: %s\n", strerror(-r));
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (p.error)
	fprintf(stderr, "Error updating account information:\n%s\n", p.error);
      else
	fprintf(stderr, "Error updating account information:\n%s\n", error_id);
      return -EIO;
    }

  if (!quiet)
    printf("Password changed.\n");

  return 0;
}

int
main(int argc, char **argv)
{
  const char *user = NULL;
  int args = 0;
  int pam_flags = 0;
  bool quiet = false;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"delete",      no_argument,       NULL, 'd' },
	  {"expire",      no_argument,       NULL, 'e' },
          {"help",        no_argument,       NULL, 'h' },
          {"keep-tokens", no_argument,       NULL, 'k' },
	  {"lock",        no_argument,       NULL, 'l' },
	  {"quiet",       no_argument,       NULL, 'q' },
	  {"status",      no_argument,       NULL, 'S' },
	  {"unlock",      no_argument,       NULL, 'u' },
	  {"version",     no_argument,       NULL, 'v' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "dehklqSuv",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'd':
	  args |= ARG_DELETE_PASSWORD;
	  break;
	case 'e':
	  args |= ARG_EXPIRE;
	  break;
        case 'h':
          print_help();
          return 0;
	case 'k':
	  pam_flags |= PAM_CHANGE_EXPIRED_AUTHTOK;
	  break;
	case 'l':
	  args |= ARG_LOCK_PASSWORD;
	  break;
	case 'q':
	  quiet = true;
	  pam_flags |= PAM_SILENT;
	  break;
	case 'S':
	  args |= ARG_STATUS_ACCOUNT;
	  break;
	case 'u':
	  args |= ARG_UNLOCK_PASSWORD;
	  break;
        case 'v':
	  printf("passwd (%s) %s\n", PACKAGE, VERSION);
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

  if (args & ARG_STATUS_ACCOUNT)
    return print_account_status(user);
  else if (args)
    return modify_account(user, args, quiet);
  else
    return chauthtok(user, pam_flags);

  return 0;
}
