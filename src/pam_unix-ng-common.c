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

#include <assert.h>

#include "basics.h"
#include "pam_unix-ng.h"

/* From pam_inline.h
 *
 * Returns NULL if STR does not start with PREFIX,
 * or a pointer to the first char in STR after PREFIX.
 */
static inline const char *
skip_prefix(const char *str, const char *prefix)
{
  assert(str);
  assert(prefix);

  size_t prefix_len = strlen(prefix);

  return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

uint32_t
parse_args(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  uint32_t ctrl = 0;

  /* does the application require quiet? */
  if (flags & PAM_SILENT)
    ctrl |= ARG_QUIET;

  /* step through arguments */
  for (; argc-- > 0; ++argv)
    {
      if (streq(*argv, "debug"))
	ctrl |= ARG_DEBUG;
      else if (streq(*argv, "quiet"))
	ctrl |= ARG_QUIET;
      else if (streq(*argv, "nullok"))
        ctrl |= ARG_NULLOK;
      /* this options are handled by pam_get_authtok() */
      else if (!streq(*argv, "try_first_pass") && !streq(*argv, "use_first_pass") &&
	       !streq(*argv, "use_authtok") && skip_prefix(*argv, "authtok_type=") == NULL)
	pam_syslog(pamh, LOG_ERR, "Unknown option: %s", *argv);
    }

  return ctrl;
}

/* write message to user */
int
write_message (pam_handle_t *pamh, int ctrl, int type,
	       const char *fmt,...)
{
  va_list ap;
  int retval;

  if (ctrl & ARG_QUIET)
    return PAM_SUCCESS;

  va_start (ap, fmt);
  retval = pam_vprompt (pamh, type, NULL, fmt, ap);
  va_end (ap);

  return retval;
}
