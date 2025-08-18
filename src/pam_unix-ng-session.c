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
#include "pam_unix-ng.h"
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
      if (PWACCESS_IS_NOT_RUNNING(r))
	return PAM_SYSTEM_ERR; /* XXX try local fallback */

      if (r == -ENOENT)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess user record failed: %s",
		 error ? error : strerror(-r));
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
