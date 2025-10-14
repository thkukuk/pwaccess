// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"
#include "verify.h"

static int
authenticate(pam_handle_t *pamh, uint32_t ctrl, uint32_t fail_delay)
{
  bool authenticated = false;
  _cleanup_free_ char *error = NULL;
  const char *user = NULL;
  const char *password = NULL;
  int  r;

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=xxx */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  /* can this happen? */
  if (isempty(user))
    return PAM_USER_UNKNOWN;

  if (!valid_name(user))
    {
      pam_syslog(pamh, LOG_ERR, "username contains invalid characters");
      return PAM_USER_UNKNOWN;
    }
  else if (ctrl & ARG_DEBUG)
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

  if (fail_delay != 0)
    {
      r = pam_fail_delay(pamh, fail_delay*1000);   /* convert milliseconds to microseconds */
      if (r != PAM_SUCCESS)
	{
	  if (ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "pam_fail_delay failed: return %d", r);
	  pam_syslog(pamh, LOG_CRIT, "Could not set fail delay");

	  return r;
	}
    }

  r = authenticate_user(pamh, ctrl, user, password, &authenticated, &error);
  if (r != PAM_SUCCESS)
    return r;

  if (authenticated)
    return PAM_SUCCESS;
  else
    log_authentication_failure(pamh, user);

  return PAM_AUTH_ERR;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  struct timespec start, stop;
  uint32_t fail_delay = 2000;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, &fail_delay);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &start);
      pam_syslog(pamh, LOG_DEBUG, "authenticate called");
    }

  int retval = authenticate(pamh, ctrl, fail_delay);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "authenticate", retval, start, stop);
    }

  return retval;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, NULL);

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "setcred called");

  return PAM_SUCCESS;
}
