// SPDX-License-Identifier: BSD-2-Clause

#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "basics.h"
#include "no_new_privs.h"

/* XXX add flags */
static void
log_debug_info(pam_handle_t *pamh, const char *type,
	       int flags)
{
  const void *service = NULL;
  const void *user = NULL;
  const void *ruser = NULL;
  const void *rhost = NULL;
  const void *tty = NULL;
  const char *login_name;

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
             "user=%s%s",
	     strna(service), type, flags,
             strna(login_name), getuid(), geteuid(),
             strna(tty), strna(ruser), strna(rhost),
             strna(user), no_new_privs_enabled()?", no_new_privs=1":"");
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
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc _unused_, const char **argv _unused_)
{
  log_debug_info(pamh, "session(close)", flags);
  return PAM_IGNORE;
}
