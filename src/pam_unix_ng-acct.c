// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"

static int
acct_mgmt(pam_handle_t *pamh, uint32_t ctrl)
{
  pwa_expire_flag_t expire_state;
  const void *void_str;
  const char *user;
  _cleanup_free_ char *error = NULL;
  long daysleft = -1;
  int r;
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
      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess expired failed: %s",
		 error ? error : strerror(-r));

      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

      return PAM_SYSTEM_ERR;
    }
  expire_state = r;

  switch (expire_state)
    {
    case PWA_EXPIRED_NO:
      break;
    case PWA_EXPIRED_YES:
      pam_syslog(pamh, LOG_NOTICE,
		 "account %s has expired (account expired)",
		 user);
      write_message(pamh, ctrl, PAM_ERROR_MSG,
		    "Your account has expired; please contact your system administrator.");
      retval = PAM_ACCT_EXPIRED;
      break;
    case PWA_EXPIRED_CHANGE_PW:
      if (daysleft == 0)
	{
	  pam_syslog(pamh, LOG_NOTICE,
		     "expired password for user %s (admin enforced)",
		     user);
	  write_message(pamh, ctrl, PAM_ERROR_MSG,
			"You are required to change your password immediately (administrator enforced).");
	}
      else
	{
	  pam_syslog(pamh, LOG_NOTICE,
		     "expired password for user %s (password aged)", user);
	  write_message(pamh, ctrl, PAM_ERROR_MSG,
			"You are required to change your password immediately (password expired).");
	}
      retval = PAM_NEW_AUTHTOK_REQD;
      break;
    case PWA_EXPIRED_DISABLED:
      pam_syslog(pamh, LOG_NOTICE,
		 "account %s has expired (failed to change password)",
		 user);
      write_message(pamh, ctrl, PAM_ERROR_MSG,
		    "Your account has expired; please contact your system administrator.");
      retval = PAM_AUTHTOK_EXPIRED;
      break;
    default:
      pam_syslog(pamh, LOG_ERR, "Unexpected expire value: %i", r);
      retval = PAM_SYSTEM_ERR;
    }

  if (daysleft >= 0)
    {
      pam_syslog(pamh, LOG_INFO,
		 "password for user %s will expire in %ld days",
		 user, daysleft);
      write_message(pamh, ctrl, PAM_TEXT_INFO,
		    "Warning: your password will expire in %ld %s.",
		    daysleft, (daysleft == 1)?"day":"days");
    }

  return retval;
}


int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  struct timespec start, stop;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
      pam_syslog(pamh, LOG_DEBUG, "acct_mgmt called");
    }

  int retval = acct_mgmt(pamh, ctrl);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

      uint64_t delta_us = (stop.tv_sec - start.tv_sec) * 1000000 + (stop.tv_nsec - start.tv_nsec) / 1000;
      pam_syslog(pamh, LOG_DEBUG, "acct_mgmt finished (%i), executed in %lu milliseconds", retval, delta_us);
    }

  return retval;
}
