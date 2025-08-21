// SPDX-License-Identifier: BSD-2-Clause

#include <assert.h>

#include "basics.h"
#include "pam_unix_ng.h"

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
