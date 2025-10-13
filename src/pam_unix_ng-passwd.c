// SPDX-License-Identifier: BSD-2-Clause

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
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, NULL);

  if (flags & PAM_CHANGE_EXPIRED_AUTHTOK)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "chauthtok called (only expired authtok)");
    }
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
