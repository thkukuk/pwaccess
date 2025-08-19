/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2025, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <pwd.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  pwa_expire_flag_t expire_state;
  const void *void_str;
  const char *user;
  _cleanup_free_ char *error = NULL;
  long daysleft = -1;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);
  int r;
  int retval = PAM_SUCCESS;

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "acct_mgmt called");

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
      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess expired failed: %s", error ? error : strerror(-r));
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
      if (daysleft == 1)
	write_message(pamh, ctrl, PAM_TEXT_INFO,
		      "Warning: your password will expire in %ld day.",
		      daysleft);
      else
	write_message(pamh, ctrl, PAM_TEXT_INFO,
		      "Warning: your password will expire in %ld days.",
		      daysleft);
    }

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "acct_mgmt done (%i)", retval);

  return retval;
}
