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
authenticate(pam_handle_t *pamh, struct config_t *cfg)
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
      if (cfg->ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  /* can this happen? */
  if (isempty(user))
    return PAM_USER_UNKNOWN;
  // this can be an `else if` since it's all related
  if (!valid_name(user))
    {
      pam_syslog(pamh, LOG_ERR, "username contains invalid characters");
      return PAM_USER_UNKNOWN;
    }
  else if (cfg->ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "username [%s]", user);

  /* XXX Don't prompt for a password if it is empty */

  /* get the users password */
  r = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL /* prompt */);
  if (r != PAM_SUCCESS)
    {
      if (cfg->ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_authtok failed: return %d", r);
      if (r != PAM_CONV_AGAIN)
	pam_syslog(pamh, LOG_CRIT, "Could not get password for [%s]", user);

      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  if (cfg->fail_delay != 0)
    {
      /* convert milliseconds to microseconds */
      r = pam_fail_delay(pamh, cfg->fail_delay*1000);
      if (r != PAM_SUCCESS)
	{
	  if (cfg->ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "pam_fail_delay failed: return %d", r);
	  pam_syslog(pamh, LOG_CRIT, "Could not set fail delay");

	  return r;
	}
    }

  r = authenticate_user(pamh, cfg->ctrl, user, password, &authenticated, &error);
  if (error)
    pam_error(pamh, "%s", error);
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
  struct config_t cfg;
  int r;

  r = parse_args(pamh, flags, argc, argv, &cfg, false);
  if (r < 0)
    return errno_to_pam(r);

  if (cfg.ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &start);
      pam_syslog(pamh, LOG_DEBUG, "authenticate called");
    }

  r = authenticate(pamh, &cfg);

  if (cfg.ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "authenticate", r, start, stop);
    }

  return r;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  struct config_t cfg;
  int r;

  r = parse_args(pamh, flags, argc, argv, &cfg, false);
  if (r < 0)
    return errno_to_pam(r);

  if (cfg.ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "setcred called");

  return PAM_SUCCESS;
}
