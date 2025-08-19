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
pam_sm_authenticate (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  uint32_t ctrl = parse_args (pamh, flags, argc, argv);
  bool nullok;
  bool authenticated = false;
  _cleanup_free_ char *error = NULL;
  const char *user = NULL;
  const char *password = NULL;
  int  r;

  if (ctrl & ARG_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "authenticate called");

  nullok = ctrl & ARG_NULLOK;

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=XXX */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog (pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "username [%s]", user);

  /* XXX Don't prompt for a password if it is empty */

  /* get the users password */
  r = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL /* prompt */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog (pamh, LOG_DEBUG, "pam_get_authtok failed: return %d", r);
      if (r != PAM_CONV_AGAIN)
	pam_syslog(pamh, LOG_CRIT, "Could not get password for [%s]", user);

      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  r = pwaccess_verify_password(user, password, nullok, &authenticated, &error);
  if (r < 0)
    {
      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess verify failed: %s", error ? error : strerror(-r));
      return PAM_SYSTEM_ERR;
    }

  if (authenticated)
    return PAM_SUCCESS;

  return PAM_AUTH_ERR;
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
  uint32_t ctrl = parse_args (pamh, flags, argc, argv);

  if (ctrl & ARG_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "setcred called");

  return PAM_SUCCESS;
}
