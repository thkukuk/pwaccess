// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <security/pam_modutil.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"
#include "verify.h"

static int
authenticate(pam_handle_t *pamh, uint32_t ctrl, uint32_t fail_delay)
{
  bool nullok;
  bool authenticated = false;
  _cleanup_free_ char *error = NULL;
  const char *user = NULL;
  const char *password = NULL;
  int  r;

  nullok = ctrl & ARG_NULLOK;

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=XXX */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  /* can this happen? */
  if (isempty(user))
    return PAM_USER_UNKNOWN;

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "username [%s]", user);

  /* XXX Don't prompt for a password if it is empty */

  /* get the users password */
  r = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL /* prompt */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_authtok failed: return %d", r);
      if (r != PAM_CONV_AGAIN)
	pam_syslog(pamh, LOG_CRIT, "Could not get password for [%s]", user);

      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  if (fail_delay != 0)
    {
      r = pam_fail_delay(pamh, fail_delay*1000);   /* convert milliseconds to microseconds */
      if (r != PAM_SUCCESS)
	{
	  if (ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "pam_fail_delay failed: return %d", r);
	  pam_syslog(pamh, LOG_CRIT, "Could not set fail delay");

	  return r;
	}
    }

  r = pwaccess_verify_password(user, password, nullok, &authenticated, &error);
  if (r < 0)
    {
      if (r == -ENODATA)
	return PAM_USER_UNKNOWN;

      pam_syslog(pamh, LOG_ERR, "pwaccess verify failed: %s",
		 error ? error : strerror(-r));

      if (PWACCESS_IS_NOT_RUNNING(r))
	{
	  struct passwd pwdbuf;
	  struct passwd *pw = NULL;
	  struct spwd spbuf;
	  struct spwd *sp = NULL;
	  _cleanup_free_ char *buf = NULL;
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
		  /* XXX error_user_not_found(link, -1, p.name); */
		  pam_error(pamh, "User not found");
		  return PAM_USER_UNKNOWN;
		}

	      pam_syslog(pamh, LOG_WARNING, "getpwnam_r(): %s", strerror(r));
	      pam_error(pamh, "getpwnam_r(): %s", strerror(r));
	      return PAM_SYSTEM_ERR;
	    }

	  /* XXX check that pw->pw_passwd is non NULL */
	  _cleanup_free_ char *hash = strdup(pw->pw_passwd);
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
	      /* XXX check that sp->sp_pwdp is non NULL */
	      hash = strdup(sp->sp_pwdp);
	      if (hash == NULL)
		{
		  pam_syslog(pamh, LOG_CRIT, "Out of memory!");
		  pam_error(pamh, "Out of memory!");
		  return PAM_BUF_ERR;
		}
	    }
	  r = verify_password(hash, password, nullok);
	  if (r == VERIFY_OK)
	    authenticated = true;
	  else if (r != VERIFY_FAILED) /* XXX error message why it failed */
	    return PAM_SYSTEM_ERR;
	}
      else
	return PAM_SYSTEM_ERR;
    }

  if (authenticated)
    return PAM_SUCCESS;
  else
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

  return PAM_AUTH_ERR;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  struct timespec start, stop;
  uint32_t fail_delay = 2000;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, &fail_delay);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &start);
      pam_syslog(pamh, LOG_DEBUG, "authenticate called");
    }

  int retval = authenticate(pamh, ctrl, fail_delay);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "authenticate", retval, start, stop);
    }

  return retval;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, NULL);

  if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "setcred called");

  return PAM_SUCCESS;
}
