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
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  uint32_t ctrl = parse_args(pamh, flags, argc, argv);

  if (flags & PAM_PRELIM_CHECK)
    {
      if (ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (prelim check)");
    }
  else if (flags & PAM_UPDATE_AUTHTOK)
    {
      if (ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (update authtok)");
    }
  else
    {
      pam_syslog(pamh, LOG_ERR, "chauthtok called without flag!");
      return PAM_SYSTEM_ERR;
    }

  return PAM_IGNORE;
}
