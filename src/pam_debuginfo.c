// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <errno.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

#include "basics.h"
#include "no_new_privs.h"

static void
freeconp(char **p)
{
#ifdef WITH_SELINUX
  if (!p || !*p)
    return;

  freecon(*p);
  *p = NULL;
#else
  (void)p;
#endif
}

static const char *
selinux_status(pam_handle_t *pamh)
{
#ifdef WITH_SELINUX
  if (is_selinux_enabled() > 0)
    {
      int r = security_getenforce();
      switch (r)
	{
        case 1:
	  return ", selinux=enforcing";
	  break;
        case 0:
	  return ", selinux=permissive";
	  break;
        default:
	  pam_syslog(pamh, LOG_ERR, "selinux error: %s",
		     strerror(errno));
	  return ", selinux=error";
	  break;
        }
    }
  else
    return ", selinux=off";
#else
  (void)pamh;
  return "";
#endif
}

/* XXX add flags */
static void
log_info(pam_handle_t *pamh, const char *type, int flags, int loglevel)
{
  _cleanup_(freeconp) char *secon = NULL;
  const void *service = NULL;
  const void *user = NULL;
  const void *ruser = NULL;
  const void *rhost = NULL;
  const void *tty = NULL;
  const char *login_name;

  if (getcon(&secon) < 0)
    pam_syslog(pamh, LOG_ERR, "getcon() failed: %s", strerror(errno));

  pam_get_item(pamh, PAM_SERVICE, &service);
  pam_get_item(pamh, PAM_USER, &user);
  pam_get_item(pamh, PAM_RUSER, &ruser);
  pam_get_item(pamh, PAM_RHOST, &rhost);
  pam_get_item(pamh, PAM_TTY, &tty);
  login_name = pam_modutil_getlogin(pamh);

  /* XXX split flags in single bits with defines */
  pam_syslog(pamh, loglevel,
             "service=%s type=%s flags=%d "
             "logname=%s uid=%u euid=%u "
             "tty=%s ruser=%s rhost=%s "
             "user=%s%s%s%s%s",
	     strna(service), type, flags,
             strna(login_name), getuid(), geteuid(),
             strna(tty), strna(ruser), strna(rhost),
             strna(user),
	     no_new_privs_enabled()?", no_new_privs=1":"",
	     selinux_status(pamh), secon?", context=":"", secon?secon:"");
}

static int
parse_args(pam_handle_t *pamh, int flags _unused_, int argc, const char **argv,
           int *loglevel)
{
  *loglevel = LOG_DEBUG;

  /* step through arguments */
  for (; argc-- > 0; ++argv)
    {
      const char *cp;

      if ((cp = startswith(*argv, "loglevel=")) != NULL)
	{
	  if (streq(cp, "debug"))
	    *loglevel = LOG_DEBUG;
	  else if (streq(cp, "info"))
	    *loglevel = LOG_INFO;
	  else if (streq(cp, "notice"))
	    *loglevel = LOG_NOTICE;
	  else if (streq(cp, "warning"))
	    *loglevel = LOG_WARNING;
	  else if (streq(cp, "error"))
	    *loglevel = LOG_ERR;
	  else if (streq(cp, "critical"))
	    *loglevel = LOG_CRIT;
	  else if (streq(cp, "alert"))
	    *loglevel = LOG_ALERT;
	  else if (streq(cp, "emerg"))
	    *loglevel = LOG_EMERG;
	  else
	    pam_syslog(pamh, LOG_ERR, "Unknown loglevel value: %s", cp);
	}
      else
	pam_syslog(pamh, LOG_ERR, "Unknown option: %s", *argv);
    }
  return 0;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "account", flags, loglevel);
  return PAM_IGNORE;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "auth", flags, loglevel);
  return PAM_IGNORE;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "setcred", flags, loglevel);
  return PAM_IGNORE;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "password", flags, loglevel);
  return PAM_IGNORE;
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "session(open)", flags, loglevel);
  return PAM_IGNORE;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  int loglevel;

  parse_args(pamh, flags, argc, argv, &loglevel);

  log_info(pamh, "session(close)", flags, loglevel);
  return PAM_IGNORE;
}
