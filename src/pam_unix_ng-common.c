// SPDX-License-Identifier: BSD-2-Clause

#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <security/pam_modutil.h>

#include "basics.h"
#include "pwaccess.h"
#include "pam_unix_ng.h"
#include "verify.h"

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
      else if ((cp = startswith(*argv, "fail_delay=")) != NULL)
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
      else if (!streq(*argv, "try_first_pass") &&
	       !streq(*argv, "use_first_pass") &&
	       !streq(*argv, "use_authtok") &&
	       startswith(*argv, "authtok_type=") == NULL)
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
      return PAM_BUF_ERR;
    }

  *size = bufsize;

  return PAM_SUCCESS;
}

int
authenticate_user(pam_handle_t *pamh, uint32_t ctrl,
		  const char *user, const char *password,
		  bool *ret_authenticated, char **error)
{
  bool nullok = ctrl & ARG_NULLOK;
  int r;

  r = pwaccess_verify_password(user, password, nullok,
			       ret_authenticated, error);
  if (r < 0)
    {
      if (r == -ENODATA)
        return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess verify failed: %s",
                 *error ? *error : strerror(-r));

      if (PWACCESS_IS_NOT_RUNNING(r))
        {
          struct passwd pwdbuf;
          struct passwd *pw = NULL;
          struct spwd spbuf;
          struct spwd *sp = NULL;
          _cleanup_free_ char *buf = NULL;
          _cleanup_free_ char *hash = NULL;
          long bufsize;

          if (!(ctrl & ARG_QUIET))
            pam_syslog(pamh, LOG_NOTICE, "pwaccessd not running, using internal fallback code");

          r = alloc_getxxnam_buffer(pamh, &buf, &bufsize);
          if (r != PAM_SUCCESS)
            return r;

          r = getpwnam_r(user, &pwdbuf, buf, bufsize, &pw);
          if (pw == NULL)
            {
              if (r == 0)
                {
                  if (valid_name(user))
                    pam_error(pamh, "User '%s' not found", user);
                  else
                    pam_error(pamh, "User not found (contains invalid characters)");
                  return PAM_USER_UNKNOWN;
                }

              pam_syslog(pamh, LOG_WARNING, "getpwnam_r(): %s", strerror(r));
              pam_error(pamh, "getpwnam_r(): %s", strerror(r));
              return PAM_SYSTEM_ERR;
            }

          hash = strdup(strempty(pw->pw_passwd));
          if (hash == NULL)
            {
              pam_syslog(pamh, LOG_CRIT, "Out of memory!");
              pam_error(pamh, "Out of memory!");
              return PAM_BUF_ERR;
            }
          if (is_shadow(pw)) /* Get shadow entry */
            {
              /* reuse buffer,
                 !!! pw is no longer valid !!! */

              r = getspnam_r(user, &spbuf, buf, bufsize, &sp);
              if (sp == NULL)
                {
                  if (r == 0)
                    {
                      if (valid_name(user))
                        pam_error(pamh, "User '%s' not found", user);
                      else
                        pam_error(pamh, "User not found (contains invalid characters)");
                      return PAM_USER_UNKNOWN;
                    }
                  pam_syslog(pamh, LOG_WARNING, "getspnam_r(): %s", strerror(r));
                  pam_error(pamh, "getspnam_r(): %s", strerror(r));
                  return PAM_SYSTEM_ERR;
                }
              hash = mfree(hash);
              hash = strdup(strempty(sp->sp_pwdp));
              if (hash == NULL)
                {
                  pam_syslog(pamh, LOG_CRIT, "Out of memory!");
                  pam_error(pamh, "Out of memory!");
                  return PAM_BUF_ERR;
                }
            }
          r = verify_password(hash, password, nullok);
          if (r == VERIFY_OK)
            *ret_authenticated = true;
          else if (r != VERIFY_FAILED) /* XXX error message why it failed */
            return PAM_SYSTEM_ERR;
        }
      else
        return PAM_SYSTEM_ERR;
    }
  return PAM_SUCCESS;
}

void
log_authentication_failure(pam_handle_t *pamh, const char *user)
{
  const void *service = NULL;
  const void *ruser = NULL;
  const void *rhost = NULL;
  const void *tty = NULL;
  const char *login_name;

  pam_get_item(pamh, PAM_SERVICE, &service);
  pam_get_item(pamh, PAM_RUSER, &ruser);
  pam_get_item(pamh, PAM_RHOST, &rhost);
  pam_get_item(pamh, PAM_TTY, &tty);
  login_name = pam_modutil_getlogin(pamh);

  pam_syslog(pamh, LOG_NOTICE,
	     "authentication failure; "
	     "logname=%s uid=%d euid=%d "
	     "tty=%s ruser=%s rhost=%s "
	     "user=%s",
	     strna(login_name), getuid(), geteuid(),
	     strna(tty), strna(ruser), strna(rhost),
	     user);
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
