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
acct_mgmt(pam_handle_t *pamh, struct config_t *cfg)
{
  pwa_expire_flag_t expire_state;
  const void *void_str;
  const char *user;
  _cleanup_free_ char *error = NULL;
  long daysleft = -1;
  int r;
  // using a conservative PAM_SYSTEM_ERR or similar as default would be
  // appreciated here, should an early return of this value ever slip in in
  // the future.
  // or, alternatively/additionally, declare this variable only below in front
  // of the `switch()` statement. We can already enjoy the merits of C99 and
  // don't need to declare everything strictly at the top anymore.
  int retval = PAM_SUCCESS;

  r = pam_get_item(pamh, PAM_USER, &void_str);
  if (r != PAM_SUCCESS || isempty(void_str))
    {
      pam_syslog(pamh, LOG_ERR, "Unknown user");
      return PAM_USER_UNKNOWN;
    }
  user = void_str;

  r = pwaccess_check_expired(user, &daysleft, NULL /* pwchangeable */, &error);
  if (r < 0)
    {
      if (r == -ENODATA)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess expired failed: %s",
		 error ? error : strerror(-r));

      // The body of this `if` block could be candidate for placing it into a
      // dedicated function, since it is performing a very specific fallback
      // purpose.
      //
      // Beyond that, is this fallback really necessary? Could this be solved
      // on PAM configuration level instead e.g. by configured the old
      // `pam_unix` module as a fallback instead?
      //
      // The support for reading /etc/shadow even if the caller has
      // insufficient privileges will be lost in this case anyway.
      // Thus the fallback feels a bit strange to me at first look: apart from
      // partly duplicating logic present already in the Varlink service end,
      // this fallback cannot really fulfill the promise that the pwaccessd
      // service makes, so there can be two very different outcomes in this
      // PAM service call, depending on whether the daemon is available or
      // not.
      if (PWACCESS_IS_NOT_RUNNING(r))
	{
	  struct spwd spbuf;
	  struct spwd *sp = NULL;
	  _cleanup_free_ char *buf = NULL;
	  long bufsize = 0;

	  if (!(cfg->ctrl & ARG_QUIET))
	    pam_syslog(pamh, LOG_NOTICE, "pwaccessd not running, using internal fallback code");

	  r = alloc_getxxnam_buffer(pamh, &buf, &bufsize);
	  if (r != PAM_SUCCESS)
	    return r;

	  r = getspnam_r(user, &spbuf, buf, bufsize, &sp);
	  if (sp == NULL)
	    {
	      if (r == 0)
		{
		  // maybe shorten this a bit:
		  //const char *cp = valid_name(user) ? user : "";
		  const char *cp;

		  if (!valid_name(user))
		    cp = "";
		  else
		    cp = user;
		  pam_syslog(pamh, LOG_INFO, "User '%s' not found", strna(cp));
		  return PAM_USER_UNKNOWN;
		}

	      pam_syslog(pamh, LOG_WARNING, "getspnam_r(): %s", strerror(r));
	      pam_error(pamh, "getspnam_r(): %s", strerror(r));
	      return PAM_SYSTEM_ERR;
	    }
	  r = expired_check(sp, &daysleft, NULL /* pwchangeable */);
	}
      else
	return PAM_SYSTEM_ERR;
    }
  // the whole stack variable declaration can be moved here, or even do it
  // like
  //
  // switch ((pwa_expire_flag_t)r) {
  //    ...
  // }
  //
  // this way you will get the smallest possible scope for the variable of
  // this type.
  expire_state = r;

  switch (expire_state)
    {
    case PWA_EXPIRED_NO:
      break;
    case PWA_EXPIRED_ACCT:
      pam_syslog(pamh, LOG_NOTICE,
		 "account %s has expired (account expired)",
		 user);
      pam_error(pamh, "Your account has expired; please contact your system administrator.");
      retval = PAM_ACCT_EXPIRED;
      break;
    case PWA_EXPIRED_CHANGE_PW:
      if (daysleft == 0)
	{
	  pam_syslog(pamh, LOG_NOTICE,
		     "expired password for user %s (admin enforced)", user);
	  pam_error(pamh, "You are required to change your password immediately (administrator enforced).");
	}
      else
	{
	  pam_syslog(pamh, LOG_NOTICE,
		     "expired password for user %s (password aged)", user);
	  pam_error(pamh, "You are required to change your password immediately (password expired).");
	}
      retval = PAM_NEW_AUTHTOK_REQD;
      break;
    case PWA_EXPIRED_PW:
      // inactive password? is this similar to a locked account? sounds a bit
      // strange.
      pam_syslog(pamh, LOG_NOTICE,
		 "password for user %s is inactive", user);
      pam_error(pamh, "Your password is inactive; please contact your system administrator.");
      retval = PAM_AUTHTOK_EXPIRED;
      break;
    default:
      pam_syslog(pamh, LOG_ERR, "Unexpected expire value: %i", r);
      retval = PAM_SYSTEM_ERR;
      // break missing, better to have this to prevent future issues
    }

  if (daysleft >= 0)
    {
      pam_syslog(pamh, LOG_INFO,
		 "password for user %s will expire in %ld days",
		 user, daysleft);
      if (!(cfg->ctrl & ARG_QUIET))
	pam_info(pamh, "Warning: your password will expire in %ld %s.",
		 daysleft, (daysleft == 1)?"day":"days");
    }

  return retval;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
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
      pam_syslog(pamh, LOG_DEBUG, "acct_mgmt called");
    }

  r = acct_mgmt(pamh, &cfg);

  if (cfg.ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "acct_mgmt", r, start, stop);
    }

  return r;
}
