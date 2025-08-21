// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <security/pam_modutil.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"


static int
authenticate(pam_handle_t *pamh, uint32_t ctrl)
{
  bool nullok;
  bool authenticated = false;
  _cleanup_free_ char *error = NULL;
  const char *user = NULL;
  const char *password = NULL;
  int  r;

  nullok = ctrl & ARG_NULLOK;

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=XXX */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  /* can this happen? */
  if (isempty(user))
    return PAM_USER_UNKNOWN;

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "username [%s]", user);

  /* XXX Don't prompt for a password if it is empty */

  /* get the users password */
  r = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL /* prompt */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_authtok failed: return %d", r);
      if (r != PAM_CONV_AGAIN)
	pam_syslog(pamh, LOG_CRIT, "Could not get password for [%s]", user);

      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  r = pwaccess_verify_password(user, password, nullok, &authenticated, &error);
  if (r < 0)
    {
      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess verify failed: %s",
		 error ? error : strerror(-r));

      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

      return PAM_SYSTEM_ERR;
    }

  if (authenticated)
    return PAM_SUCCESS;
  else
    {
      const void *service = NULL;
      const void *ruser = NULL;
      const void *rhost = NULL;
      const void *tty = NULL;
      const char *login_name;

      pam_get_item(pamh, PAM_SERVICE, &service);
      pam_get_item(pamh, PAM_RUSER, &ruser);
      pam_get_item(pamh, PAM_RHOST, &rhost);
      pam_get_item(pamh, PAM_TTY, &tty);
      login_name = pam_modutil_getlogin(pamh);

      pam_syslog(pamh, LOG_NOTICE,
		 "authentication failure; "
		 "logname=%s uid=%d euid=%d "
		 "tty=%s ruser=%s rhost=%s "
		 "user=%s",
		 strna(login_name), getuid(), geteuid(),
		 strna(tty), strna(ruser), strna(rhost),
		 user);
    }

  return PAM_AUTH_ERR;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  struct timespec start, stop;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
      pam_syslog(pamh, LOG_DEBUG, "authenticate called");
    }

  int retval = authenticate(pamh, ctrl);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

      uint64_t delta_us = (stop.tv_sec - start.tv_sec) * 1000000 + (stop.tv_nsec - start.tv_nsec) / 1000;
      pam_syslog(pamh, LOG_DEBUG, "authenticate finished (%i), executed in %lu milliseconds", retval, delta_us);
    }

  return retval;
}


int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "setcred called");

  return PAM_SUCCESS;
}
