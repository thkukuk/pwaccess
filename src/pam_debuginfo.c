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
log_debug_info(pam_handle_t *pamh, const char *type, int flags)
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
  pam_syslog(pamh, LOG_DEBUG,
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

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "account", flags);
  return PAM_IGNORE;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "auth", flags);
  return PAM_IGNORE;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "setcred", flags);
  return PAM_IGNORE;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "password", flags);
  return PAM_IGNORE;
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "session(open)", flags);
  return PAM_IGNORE;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "session(close)", flags);
  return PAM_IGNORE;
}
