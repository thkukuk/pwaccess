// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  const void *void_str;
  const char *user;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);
  int r;

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "open_session called");

  /* don't do anything if we don't log it */
  if (ctrl & ARG_QUIET)
    return PAM_SUCCESS;

  r = pam_get_item(pamh, PAM_USER, &void_str);
  if (r != PAM_SUCCESS || isempty(void_str))
    {
      pam_syslog(pamh, LOG_ERR, "open_session - user is not known?");
      return PAM_SESSION_ERR;
    }
  user = void_str;

  _cleanup_free_ char *error = NULL;
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  bool complete = false;
  char buffer[64];
  char *logname = buffer;

  if (getlogin_r(buffer, sizeof(buffer)) != 0)
    logname = strerror(errno);

  r = pwaccess_get_user_record(-1, user, &pw, NULL, &complete, &error);
  if (r < 0)
    {
      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess user record failed: %s",
		 error ? error : strerror(-r));

      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

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
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);
  int r;

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "close_session called");

  /* don't do anything if we don't log it */
  if (ctrl & ARG_QUIET)
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
