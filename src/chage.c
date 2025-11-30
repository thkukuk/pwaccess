// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <locale.h>
#include <getopt.h>
#include <shadow.h>
#include <stdbool.h>
#include <libeconf.h>
#include <systemd/sd-varlink.h>

#include "basics.h"
#include "pwaccess.h"
#include "varlink-client-common.h"
#include "get_value.h"
#include "get_logindefs.h"
#include "drop_privs.h"

#define DAY (24L*3600L)
#define SCALE DAY

static int
oom(void)
{
  fprintf(stderr, "Out of memory!\n");
  return ENOMEM;
}

/* convert a string to a time_t value and return it as number
   of days since 1.1.1970.  */
static long int
str2date(const char *str)
{
  struct tm tp;
  char *cp;
  time_t result;

  if (streq(str, "1969-12-31"))
    return -1;

  memset(&tp, 0, sizeof tp);
  cp = strptime(str, "%Y-%m-%d", &tp);
  if (!cp || *cp != '\0')
    return -1;

  result = mktime(&tp);
  if (result == (time_t) -1)
    return -1;

  return (result + (DAY/2)) / DAY;
}

/* convert time_t into a readable date string.  */
static char *
date2str(time_t date)
{
  struct tm *tp;
  char buf[20];

  tp = gmtime(&date);
  if (strftime(buf, sizeof(buf), "%Y-%m-%d", tp) == 0)
    {
      fprintf(stderr, "strftime failed!\n");
      return NULL;
    }
  return strdup(buf);
}


/* Print the time in a human readable format.  */
static void
print_date(time_t date, bool iso8601)
{
  struct tm *tp;
  char buf[40];

  tp = gmtime(&date);
  if (strftime(buf, sizeof buf, iso8601?"%F":"%b %d, %Y", tp) == 0)
    {
      fprintf(stderr, "strftime failed!\n");
      return;
    }
  puts(buf);
}

/* Print the current values of the expiration fields.  */
static int
print_shadow_info (const char *user, struct spwd *sp, bool iso8601)
{
  if (sp == NULL)
    {
      fprintf(stderr, "ERROR: No shadow entry for user '%s' found.\n", user);
      return ENODATA;
    }

  printf ("Last password change:\t\t");
  if (sp->sp_lstchg == 0)
    printf("password change enforced\n");
  else if (sp->sp_lstchg < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE, iso8601);

  printf("Password expires:\t\t");
  if (sp->sp_lstchg < 0 || sp->sp_max >= 10000 * (DAY / SCALE)
      || sp->sp_max < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE + sp->sp_max * SCALE, iso8601);

  printf("Password inactive:\t\t");
  if (sp->sp_lstchg < 0 || sp->sp_inact < 0 ||
      sp->sp_max >= 10000 * (DAY / SCALE) || sp->sp_max < 0)
    printf("never\n");
  else
    print_date(sp->sp_lstchg * SCALE +
               (sp->sp_max + sp->sp_inact) * SCALE, iso8601);

  printf("Account expires:\t\t");
  if (sp->sp_expire < 0)
    printf("never\n");
  else
    print_date(sp->sp_expire * SCALE, iso8601);

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

static int
update_account(const struct passwd *pw, const struct spwd *sp)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *passwd = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *shadow = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
  _cleanup_free_ char *error = NULL;
  _cleanup_(struct_result_free) struct result p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct result, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct result, error), 0 },
    {}
  };
  const char *error_id = NULL;
  int r;

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

  if (pw)
    {
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
    }

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

  r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_VARIANT("shadow", shadow));
  if (r >= 0 && passwd)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_VARIANT("passwd", passwd));
  if (r < 0)
    {
      fprintf(stderr, "JSON merge result object failed: %s", strerror(-r));
      return -r;
    }
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

  printf("Account information changed.\n");
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

  fputs("  -d, --lastday <date>     Set date of last password change\n", stdout);
  fputs("  -E, --expiredate <date>  Date on which user's password expires\n", stdout);
  fputs("  -i, --iso8601            Print dates as YYYY-MM-DD\n", stdout);
  fputs("  -I, --inactive <days>    Lock expired account after inactive days\n", stdout);
  fputs("  -l, --list               List account aging information\n", stdout);
  fputs("  -m, --mindays <days>     Minimum # of days before password can be changed\n", stdout);
  fputs("  -M, --maxdays <days>     Maximum # of days before password can be canged\n", stdout);
  fputs("  -h, --help               Give this help list\n", stdout);
  fputs("  -v, --version            Print program version\n", stdout);
  fputs("  -W, --warndays <days>    # days of warning before password expires\n", stdout);
  fputs("<date> must be in the form of \"YYYY-MM-DD\"\n", stdout);
}

static void
print_error(void)
{
  fprintf(stderr, "Try `chage --help' for more information.\n");
}

int
main(int argc, char **argv)
{
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  _cleanup_free_ char *error = NULL;
  bool complete = false;
  char *user = NULL;
  char *expiredate = NULL;
  char *inactive = NULL;
  char *lastday = NULL;
  char *maxdays = NULL;
  char *mindays = NULL;
  char *warndays = NULL;
  int i_flag = 0;
  int l_flag = 0;
  int r;

  setlocale(LC_ALL, "");

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"expiredate", required_argument, NULL, 'E' },
	  {"help",       no_argument,       NULL, 'h' },
	  {"inactive",   required_argument, NULL, 'I' },
	  {"iso8601",    no_argument,       NULL, 'i' },
	  {"lastday",    required_argument, NULL, 'd' },
	  {"list",       no_argument,       NULL, 'l' },
	  {"maxdays",    required_argument, NULL, 'M' },
	  {"mindays",    required_argument, NULL, 'm' },
	  {"version",    no_argument,       NULL, 'v' },
	  {"warndays",   required_argument, NULL, 'W' },
	  {NULL,         0,                 NULL, '\0'}
        };

      c = getopt_long(argc, argv, "E:hI:id:lM:m:vW:",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'E':
	  expiredate = optarg;
	  break;
	case 'I':
	  inactive = optarg;
	  break;
	case 'i':
	  i_flag = 1;
	  break;
	case 'd':
	  lastday = optarg;
	  break;
	case 'M':
	  maxdays = optarg;
	  break;
	case 'm':
	  mindays = optarg;
	  break;
	case 'W':
	  warndays = optarg;
	  break;
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
          return EINVAL;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc == 1)
    user = argv[0];

  if (argc > 1)
    {
      fprintf(stderr, "chage: Too many arguments.\n");
      print_error();
      return EINVAL;
    }

  if (l_flag && (expiredate || inactive || lastday || maxdays ||
		 mindays || warndays))
    {
      fprintf(stderr, "The --list option cannot be combined with other options.\n");
      print_error();
      return EINVAL;
    }

  r = check_and_drop_privs();
  if (r < 0)
    return -r;

  /* get user account data */
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
      return ENODATA;
    }
  if (!complete)
    {
      fprintf(stderr, "Permission denied.\n");
      return EPERM;
    }
  if (!user)
    user = pw->pw_name;

  /* execute options */
  if (l_flag)
    return print_shadow_info(user, sp, i_flag);

  if (getuid() != 0)
    {
      fprintf(stderr, "Permission denied.\n");
      return EPERM;
    }

  /* create default shadow entry if there is none */
  bool pw_changed = false;
  char *ep;

  if (!sp)
    {
      sp = calloc(1, sizeof(struct spwd));
      if (!sp)
	return oom();
      sp->sp_namp = strdup(pw->pw_name);
      if (!sp->sp_namp)
	return oom();
      sp->sp_pwdp = pw->pw_passwd;
      pw->pw_passwd = strdup("x");
      if (!pw->pw_passwd)
	return oom();
      pw_changed = true;
      sp->sp_lstchg = time(NULL) / DAY;
      /* disable instead of requesting password change */
      if (!sp->sp_lstchg)
	sp->sp_lstchg = -1;
      sp->sp_min = get_logindefs_num("PASS_MIN_DAYS", -1);
      sp->sp_max = get_logindefs_num("PASS_MAX_DAYS", -1);
      sp->sp_warn = get_logindefs_num("PASS_WARN_AGE", -1);
      sp->sp_inact = -1;
      sp->sp_expire = -1;
    }

  /* Use user provided values */
  if (!(expiredate || inactive || lastday || maxdays || mindays || warndays))
    {
      char buf[80];

      /* XXX consolidate in a single function */
      snprintf(buf, sizeof(buf), "%ld", sp->sp_min);
      r = get_value(buf, "Minimum password age", &mindays);
      if (r < 0)
	return -r;
      if (mindays == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
      snprintf(buf, sizeof(buf), "%ld", sp->sp_max);
      r = get_value(buf, "Maximum password age", &maxdays);
      if (r < 0)
	return -r;
      if (maxdays == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
      if (sp->sp_lstchg == -1)
	strcpy(buf, "-1");
      else
	{
	  _cleanup_free_ char *p = NULL;

	  p = date2str(sp->sp_lstchg*SCALE);
	  if (p != NULL)
	    strlcpy(buf, p, sizeof(buf));
	  else
	    strcpy(buf, "-1");
	}
      r = get_value(buf, "Last password change (YYYY-MM-DD)", &lastday);
      if (r < 0)
	return -r;
      if (lastday == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
      snprintf(buf, sizeof(buf), "%ld", sp->sp_warn);
      r = get_value(buf, "Password warning period", &warndays);
      if (r < 0)
	return -r;
      if (warndays == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
      snprintf(buf, sizeof(buf), "%ld", sp->sp_inact);
      r = get_value(buf, "Password inactivity period", &inactive);
      if (r < 0)
	return -r;
      if (inactive == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
      if (sp->sp_expire == -1)
	strcpy(buf, "-1");
      else
	{
	  _cleanup_free_ char *p = NULL;

	  p = date2str(sp->sp_expire*SCALE);
	  if (p != NULL)
	    strlcpy(buf, p, sizeof(buf));
	  else
	    strcpy(buf, "-1");
	}
      r = get_value(buf, "Account expires (YYYY-MM-DD)", &expiredate);
      if (r < 0)
	return -r;
      if (expiredate == NULL)
	{
	  fprintf(stderr, "chage aborted.\n");
	  return ENODATA;
	}
    }

  /* values are provided as option or asked for */
  if (mindays)
    {
      long l;

      errno = 0;
      l = strtol(mindays, &ep, 10);
      if (errno == ERANGE || l < -1 || mindays == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse 'mindays=%s'\n", mindays);
	  return EINVAL;
	}
	  sp->sp_min = l;
    }

  if (maxdays)
    {
      long l;

      errno = 0;
      l = strtol(maxdays, &ep, 10);
      if (errno == ERANGE || l < -1 || maxdays == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse 'maxdays=%s'\n", maxdays);
	  return EINVAL;
	}
	  sp->sp_max = l;
    }

  if (warndays)
	{
	  long l;

	  errno = 0;
	  l = strtol(warndays, &ep, 10);
	  if (errno == ERANGE || l < -1 || warndays == ep || *ep != '\0')
	    {
	      fprintf(stderr, "Cannot parse 'warndays=%s'\n", warndays);
	      return EINVAL;
	    }
	  sp->sp_warn = l;
	}

  if (inactive)
    {
      long l;

      errno = 0;
      l = strtol(inactive, &ep, 10);
      if (errno == ERANGE || l < -1 || inactive == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse 'inactive=%s'\n", inactive);
	  return EINVAL;
	}
      sp->sp_inact = l;
    }

  if (lastday)
    {
      if (streq(lastday, "1969-12-31"))
	sp->sp_lstchg = -1;
      else
	{
	  sp->sp_lstchg = str2date(lastday);
	  if (sp->sp_lstchg == -1)
	    {
	      long l;

	      errno = 0;
	      l = strtol(lastday, &ep, 10);
	      if (errno == ERANGE || l < -1 || lastday == ep || *ep != '\0')
		{
		  fprintf(stderr, "Cannot parse 'lastday=%s'\n", lastday);
		  return EINVAL;
		}
	      sp->sp_lstchg = l;
	    }
	}
    }
  if (expiredate)
    {
      if (streq(expiredate, "1969-12-31"))
	sp->sp_expire = -1;
      else
	{
	  sp->sp_expire = str2date(expiredate);
	  if (sp->sp_expire == -1)
	    {
	      long l;

	      errno = 0;
	      l = strtol(expiredate, &ep, 10);
	      if (errno == ERANGE || l < -1 || expiredate == ep || *ep != '\0')
		{
		  fprintf(stderr, "Cannot parse 'expiredate=%s'\n", expiredate);
		  return EINVAL;
		}
	      sp->sp_expire = l;
	    }
	}
    }

  return update_account(pw_changed?pw:NULL, sp);
}
