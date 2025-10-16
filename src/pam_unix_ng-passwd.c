// SPDX-License-Identifier: BSD-2-Clause

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"
#include "verify.h"
#include "files.h"

#define MAX_PASSWD_TRIES 3

static int
unix_chauthtok(pam_handle_t *pamh, int flags, uint32_t ctrl)
{
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  bool i_am_root = (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK));
  const char *only_expired_authtok = "";
  const char *user = NULL;
  int r;

  /* Validate flags */
  if (flags & PAM_CHANGE_EXPIRED_AUTHTOK)
    only_expired_authtok = ",only expired authtok";

  if (flags & PAM_PRELIM_CHECK)
    {
      if (ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (prelim check%s)", only_expired_authtok);
    }
  else if (flags & PAM_UPDATE_AUTHTOK)
    {
      if (ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (update authtok%s)", only_expired_authtok);
    }
  else
    {
      pam_syslog(pamh, LOG_ERR, "chauthtok called without flag!");
      return PAM_ABORT;
    }

  /* We must be root to update passwd and shadow. */
  if (geteuid() != 0)
    {
      const char *no_root = "Calling proces must be root!";
      pam_syslog(pamh, LOG_ERR, "%s", no_root);
      pam_error(pamh, "%s", no_root);
      return PAM_CRED_INSUFFICIENT;
    }

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=xxx */);
  if (r != PAM_SUCCESS)
    {
      if (ctrl & ARG_DEBUG)
        pam_syslog(pamh, LOG_DEBUG, "pam_get_user failed: return %d", r);
      return (r == PAM_CONV_AGAIN ? PAM_INCOMPLETE:r);
    }

  if (isempty(user))
    return PAM_USER_UNKNOWN;

  if (!valid_name(user))
    {
      pam_syslog(pamh, LOG_ERR, "username contains invalid characters");
      return PAM_USER_UNKNOWN;
    }
  else if (ctrl & ARG_DEBUG)
    pam_syslog(pamh, LOG_DEBUG, "username [%s]", user);

  r = get_local_user_record(pamh, user, &pw, &sp);
  if (r < 0)
    {
      if (r == -ENOENT)
	{
	  pam_syslog(pamh, LOG_ERR, "%s is no local user", user);
	  pam_error(pamh, "You can only change local passwords.");
	}
      else
	{
	  pam_syslog(pamh, LOG_ERR, "getting local user records failed: %s", strerror(-r));
	  pam_error(pamh, "Error getting user records");
	}
      return PAM_AUTHTOK_RECOVERY_ERR;
    }

  if (flags & PAM_PRELIM_CHECK)
    {
      const char *pass_old = NULL;
      bool authenticated = false;
      _cleanup_free_ char *error = NULL;

      /* If this is being run by root and we change a local password,
         we don't need to get the old password. The test for
         PAM_CHANGE_EXPIRED_AUTHTOK is here, because login runs as
         root and we need the old password in this case. */
      if (i_am_root)
	{
	  if (ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "process run by root, do nothing");
	  return PAM_SUCCESS;
        }

      /* XXX if (_unix_blankpasswd(pamh, ctrl, user))
	 return PAM_SUCCESS; */

      /* instruct user what is happening */
      if (!(ctrl & ARG_QUIET))
	{
	  r = pam_info(pamh, "Changing password for %s.", user);
	  if (r != PAM_SUCCESS)
	    return r;
	}

      r = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &pass_old, NULL);
      if (r != PAM_SUCCESS)
	{
	  pam_syslog(pamh, LOG_NOTICE, "password - old token not obtained");
	  return r;
	}

      r = authenticate_user(pamh, ctrl, user, pass_old, &authenticated, &error);
      pass_old = NULL;
      if (r != PAM_SUCCESS || !authenticated)
	{
	  if (error)
	    pam_syslog(pamh, LOG_ERR, "authentication error: %s", error);
	  log_authentication_failure(pamh, user);
	  if (r != PAM_SUCCESS)
	    return r;

	  return PAM_AUTH_ERR;
	}

      bool pwchangeable = true;
      r = expired_check(sp, NULL, &pwchangeable);
      if (!pwchangeable && !i_am_root)
	{
	  pam_error(pamh, "You must wait longer to change your password.");
	  return PAM_AUTHTOK_ERR;
	}
    }
  else if (flags & PAM_UPDATE_AUTHTOK)
    {
      const char *pass_old = NULL;
      const char *pass_new = NULL;
      const void *item;
      int retry = 0;

      /* Get the old password again. */
      r = pam_get_item(pamh, PAM_OLDAUTHTOK, &item);
      if (r != PAM_SUCCESS)
	{
	  pam_syslog(pamh, LOG_NOTICE, "User %s not authenticated: %s",
		     user, pam_strerror(pamh, r));
	  return r;
	}

      pass_old = item;

      r = PAM_AUTHTOK_ERR;
      while ((r != PAM_SUCCESS) && (retry++ < MAX_PASSWD_TRIES))
	{
	  const char *no_new_pass_msg = "No new password has been supplied";

	  /* use_authtok is to force the use of a previously entered
	     password -- needed for pluggable password strength checking */
	  r = pam_get_authtok(pamh, PAM_AUTHTOK, &pass_new, NULL);
	  if (r == PAM_TRY_AGAIN) /* New authentication tokens mismatch. */
	    continue;
	  if (r != PAM_SUCCESS)
	    {
	      if (ctrl & ARG_DEBUG)
		pam_syslog(pamh, LOG_DEBUG, "%s - %s", no_new_pass_msg, pam_strerror(pamh, r));
	      pass_old = NULL;
	      return r;
	    }

	  if (isempty(pass_new) || (pass_old && streq(pass_new, pass_old)))
	    {
	      /* remove new password for other modules */
	      pam_set_item(pamh, PAM_AUTHTOK, NULL);
	      if (ctrl & ARG_DEBUG)
		pam_syslog(pamh, LOG_DEBUG, "%s", no_new_pass_msg);
	      pam_error(pamh, "%s.", no_new_pass_msg);
	      r = PAM_AUTHTOK_ERR;
	    }

	  if (strlen(strempty(pass_new)) > PAM_MAX_RESP_SIZE)
	    {
	      pam_syslog(pamh, LOG_NOTICE, "supplied password to long");
	      pam_error(pamh, "You must choose a shorter password.");
	      r = PAM_AUTHTOK_ERR;
	    }
	  else if (!i_am_root)
	    {
	      size_t pass_min_len = 8; /* XXX make this configurable */
	      if (strlen(pass_new) < pass_min_len)
		{
		  pam_syslog(pamh, LOG_NOTICE, "supplied password too short");
                  pam_error(pamh, "You must choose a longer password.");
		  r = PAM_AUTHTOK_ERR;
                }
	    }
	}
      if (r != PAM_SUCCESS)
	{
	  pam_syslog(pamh, LOG_NOTICE, "new password not acceptable");
	  pass_new = pass_old = NULL; /* cleanup */
	  return r;
	}

      /* We have an approved password, create new hash and
	 change the database */

      char *new_hash = NULL;
      r = create_hash(pamh, pass_new, &new_hash);
      if (r < 0 || new_hash == NULL)
	{
	  pam_syslog(pamh, LOG_CRIT,
		     "crypt() failure or out of memory for password");
	  pass_new = pass_old = NULL; /* cleanup */
	  return PAM_BUF_ERR;
	}

      if (is_shadow(pw))
	{
	  /* we use _cleanup_ for this struct */
	  free(sp->sp_pwdp);
	  sp->sp_pwdp = strdup(new_hash);
	  if (sp->sp_pwdp == NULL)
	    return -ENOMEM;
	  sp->sp_lstchg = time(NULL) / (60 * 60 * 24);
	  if (sp->sp_lstchg == 0)
	    sp->sp_lstchg = -1; /* Don't request passwort change
				   only because time isn't set yet. */
	  r = update_shadow(sp, NULL);
	}
      else
	{
	  /* we use _cleanup_ for this struct */
	  free(pw->pw_passwd);
	  pw->pw_passwd = strdup(new_hash);
	  if (pw->pw_passwd == NULL)
	    return -ENOMEM;

	  r = update_passwd(pw, NULL);
	}
      explicit_bzero(new_hash, strlen(new_hash));
      pass_old = pass_new = NULL;
    }

  return PAM_SUCCESS;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  struct timespec start, stop;
  uint32_t ctrl = parse_args(pamh, flags, argc, argv, NULL);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &start);
      pam_syslog(pamh, LOG_DEBUG, "chauthtok called");
    }

  int retval = unix_chauthtok(pamh, flags, ctrl);

  if (ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "chauthtok", retval, start, stop);
    }

  return retval;
}
