// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"
#include "verify.h"

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  char lognamebuf[LOGIN_NAME_MAX+1];
  const char *logname = lognamebuf;
  struct passwd pwdbuf;
  struct passwd *pw = NULL;
  _cleanup_free_ char *pwbuf = NULL;
  long pwbufsize;
  const void *void_str;
  const char *user;
  struct config_t cfg;
  int r;

  r = parse_args(pamh, flags, argc, argv, &cfg, false);
  if (r < 0)
    return errno_to_pam(r);

  if (cfg.ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "open_session called");

  /* don't do anything if we don't log it */
  if (cfg.ctrl & ARG_QUIET)
    return PAM_SUCCESS;

  r = pam_get_item(pamh, PAM_USER, &void_str);
  if (r != PAM_SUCCESS || isempty(void_str))
    {
      pam_syslog(pamh, LOG_ERR, "open_session - user is not known?");
      return PAM_SESSION_ERR;
    }
  user = void_str;

  /* lognamebuf is bigger than max allowed username length */
  if (getlogin_r(lognamebuf, sizeof(lognamebuf)) != 0)
    logname = strerror(errno);

  r = alloc_getxxnam_buffer(pamh, &pwbuf, &pwbufsize);
  if (r != PAM_SUCCESS)
    return r;

  r = getpwnam_r(user, &pwdbuf, pwbuf, pwbufsize, &pw);
  if (pw == NULL)
    {
      if (r == 0)
	{
	  const char *cp;

	  if (!valid_name(user))
	    cp = "";
	  else
	    cp = user;
	  pam_syslog(pamh, LOG_INFO,  "User '%s' not found", strna(cp));
	  return PAM_USER_UNKNOWN;
	}

      pam_syslog(pamh, LOG_WARNING, "getpwnam_r(): %s", strerror(r));
      pam_error(pamh, "getpwnam_r(): %s", strerror(r));
      return PAM_SYSTEM_ERR;
    }

  pam_syslog(pamh, LOG_INFO, "session opened for user %s(uid=%lu) by %s(uid=%lu)",
	     user, (long unsigned)pw->pw_uid, logname, (long unsigned)getuid());

  return PAM_SUCCESS;

}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  const void *void_str;
  const char *user;
  struct config_t cfg;
  int r;

  r = parse_args(pamh, flags, argc, argv, &cfg, false);
  if (r < 0)
    return errno_to_pam(r);

  if (cfg.ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "close_session called");

  /* don't do anything if we don't log it */
  if (cfg.ctrl & ARG_QUIET)
    return PAM_SUCCESS;

  r = pam_get_item(pamh, PAM_USER, &void_str);
  if (r != PAM_SUCCESS || isempty(void_str))
    {
      pam_syslog(pamh, LOG_ERR, "close_session - user is not known?");
      return PAM_SESSION_ERR;
    }
  user = void_str;

  pam_syslog(pamh, LOG_INFO, "session closed for user %s", user);

  return PAM_SUCCESS;
}
