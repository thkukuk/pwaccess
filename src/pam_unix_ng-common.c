// SPDX-License-Identifier: BSD-2-Clause

#include <assert.h>
#include <limits.h>

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
parse_args(pam_handle_t *pamh, int flags, int argc, const char **argv,
	   uint32_t *fail_delay)
{
  const char *cp;
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
      else if ((cp = skip_prefix(*argv, "fail_delay=")) != NULL)
	{
	  char *ep;
	  long l;

	  if (fail_delay != NULL)
	    continue;

	  l = strtol(cp, &ep, 10);
	  if (l == LONG_MAX || l < 0 || l > UINT32_MAX ||
	      cp == ep || *ep != '\0')
	    pam_syslog(pamh, LOG_ERR, "Cannot parse 'fail_delay=%s'", cp);
	  else
	    *fail_delay = l;
	}
      /* this options are handled by pam_get_authtok() */
      else if (!streq(*argv, "try_first_pass") && !streq(*argv, "use_first_pass") &&
	       !streq(*argv, "use_authtok") && skip_prefix(*argv, "authtok_type=") == NULL)
	pam_syslog(pamh, LOG_ERR, "Unknown option: %s", *argv);
    }

  return ctrl;
}

int
alloc_getxxnam_buffer(pam_handle_t *pamh, char **buf, long *size)
{
  long bufsize;

  bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1) /* Value was indeterminate */
    bufsize = 1024;  /* sysconf() returns 1024 */

  *buf = malloc(bufsize);
  if (*buf == NULL)
    {
      pam_syslog(pamh, LOG_CRIT, "Out of memory!");
      pam_error(pamh, "Out of memory!");
      return PAM_BUF_ERR;
    }

  *size = bufsize;

  return PAM_SUCCESS;
}

void
log_runtime_ms(pam_handle_t *pamh, const char *type, int retval,
	       struct timespec start, struct timespec stop)
{
  uint64_t delta_ms = timespec_diff_ms(start, stop);

  pam_syslog(pamh, LOG_DEBUG,
	     "%s finished (%s), executed in %lu milliseconds",
	     type, pam_strerror(pamh, retval), delta_ms);
}
