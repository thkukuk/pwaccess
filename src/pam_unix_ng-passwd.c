// SPDX-License-Identifier: BSD-2-Clause

#include <assert.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "basics.h"
#include "pam_unix_ng.h"
#include "pwaccess.h"
#include "verify.h"
#include "files.h"
#include "no_new_privs.h"

#define MAX_PASSWD_TRIES 3

static int
get_local_user_record(pam_handle_t *pamh, const char *user,
		      struct passwd **ret_pw, struct spwd **ret_sp)
{
  _cleanup_fclose_ FILE *fp = NULL;
  struct passwd pw;
  struct spwd sp;
  struct passwd *pw_ptr = NULL;
  struct spwd *sp_ptr = NULL;
  _cleanup_free_ char *pwbuf;
  long pwbufsize = 0;
  _cleanup_free_ char *spbuf;
  long spbufsize = 0;
  int r;

  assert(user);
  assert(ret_pw);
  assert(ret_sp);

  *ret_pw = NULL;
  *ret_sp = NULL;

  /* Get passwd entry */
  if ((fp = fopen("/etc/passwd", "r")) == NULL)
    return -errno;

  r = alloc_getxxnam_buffer(pamh, &pwbuf, &pwbufsize);
  if (r != PAM_SUCCESS)
    return r;

  /* Loop over all passwd entries */
  r = 0;
  while (r == 0)
    {
      r = fgetpwent_r(fp, &pw, pwbuf, pwbufsize, &pw_ptr);
      if (ret_pw != NULL)
	{
	  if(streq(pw_ptr->pw_name, user))
	    break;
	}
    }
  if (r != 0)
    return -errno;

  r = fclose(fp);
  fp = NULL;
  if (r < 0)
    return -errno;

  /* Get shadow entry */
  if ((fp = fopen("/etc/shadow", "r")) == NULL)
    return -errno;

  r = alloc_getxxnam_buffer(pamh, &spbuf, &spbufsize);
  if (r != PAM_SUCCESS)
    return r;

  /* Loop over all shadow entries */
  r = 0;
  while (r == 0)
    {
      r = fgetspent_r(fp, &sp, spbuf, spbufsize, &sp_ptr);
      if (ret_sp != NULL)
	{
	  if (streq(sp_ptr->sp_namp, user))
	    break;
	}
    }
  if (r != 0)
    return -errno;

  r = fclose(fp);
  fp = NULL;
  if (r < 0)
    return -errno;

  /* ret_pw != NULL -> pw contains valid entry, duplicate that */
  if (pw_ptr)
    {
      _cleanup_(struct_passwd_freep) struct passwd *tmp = NULL;

      tmp = calloc(1, sizeof(struct passwd));
      if (tmp == NULL)
	return -ENOMEM;

      tmp->pw_name = strdup(pw.pw_name);
      tmp->pw_passwd = strdup(strempty(pw.pw_passwd));
      tmp->pw_uid = pw.pw_uid;
      tmp->pw_gid = pw.pw_gid;
      tmp->pw_gecos = strdup(strempty(pw.pw_gecos));
      tmp->pw_dir = strdup(strempty(pw.pw_dir));
      tmp->pw_shell = strdup(strempty(pw.pw_shell));
      /* if any of the string pointer is NULL, strdup failed */
      if (!tmp->pw_name || !tmp->pw_passwd || !tmp->pw_gecos ||
	  !tmp->pw_dir || !tmp->pw_shell)
	return -ENOMEM;

      *ret_pw = TAKE_PTR(tmp);
    }
  if (sp_ptr)
    {
      _cleanup_(struct_shadow_freep) struct spwd *tmp;

      tmp = calloc(1, sizeof(struct spwd));
      if (tmp == NULL)
	return -ENOMEM;

      tmp->sp_namp = strdup(sp.sp_namp);
      tmp->sp_pwdp = strdup(strempty(sp.sp_pwdp));
      tmp->sp_lstchg = sp.sp_lstchg;
      tmp->sp_min = sp.sp_min;
      tmp->sp_max = sp.sp_max;
      tmp->sp_warn = sp.sp_warn;
      tmp->sp_inact = sp.sp_inact;
      tmp->sp_expire = sp.sp_expire;
      tmp->sp_flag = sp.sp_flag;

      if (!tmp->sp_namp || !tmp->sp_pwdp)
	return -ENOMEM;

      *ret_sp = TAKE_PTR(tmp);
    }

  return 0;
}

static bool
i_am_root_detect(pam_handle_t *pamh, int flags)
{
  bool root = false;

  /* If the PAM_NO_ROOT=1 pam environment variable is set,
     use the rules for normal users, not the relaxed ones
     for root. */
  const char *no_root_env = pam_getenv(pamh, "PAM_NO_ROOT");
  if (no_root_env != NULL && streq(no_root_env, "1"))
    return false;

  /* If no_new_privs is enabled, geteuid()/getuid() are pretty useless.
     Report always that we are not root, so user as in worst case to
     enter his password more often than necessary. */
  if (no_new_privs_enabled())
    root = false;
  else
    /* The test for PAM_CHANGE_EXPIRED_AUTHTOK is here, because login
       runs as root and we need the old password in this case. */
    root = (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK));

  return root;
}

static int
unix_chauthtok(pam_handle_t *pamh, int flags, struct config_t *cfg)
{
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  bool i_am_root = i_am_root_detect(pamh, flags);
  const char *only_expired_authtok = "";
  const char *run_as_root = "";
  const char *user = NULL;
  int r;

  if (i_am_root)
    run_as_root = ", root";

  /* Validate flags */
  if (flags & PAM_CHANGE_EXPIRED_AUTHTOK)
    only_expired_authtok = ", only expired authtok";

  if (flags & PAM_PRELIM_CHECK)
    {
      if (cfg->ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (prelim check%s%s)", only_expired_authtok, run_as_root);
    }
  else if (flags & PAM_UPDATE_AUTHTOK)
    {
      if (cfg->ctrl & ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "chauthtok called (update authtok%s%s)", only_expired_authtok, run_as_root);
    }
  else
    {
      pam_syslog(pamh, LOG_ERR, "chauthtok called without flag!");
      return PAM_ABORT;
    }

  /* We must be root to update passwd and shadow. */
  if (geteuid() != 0)
    {
      const char *no_root = "Calling process must be root!";
      pam_syslog(pamh, LOG_ERR, "%s (euid=%u,uid=%u)", no_root,
		 geteuid(), getuid());
      pam_error(pamh, "%s", no_root);
      return PAM_CRED_INSUFFICIENT;
    }

  /* Get login name */
  r = pam_get_user(pamh, &user, NULL /* prompt=xxx */);
  if (r != PAM_SUCCESS)
    {
      if (cfg->ctrl & ARG_DEBUG)
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
  else if (cfg->ctrl & ARG_DEBUG)
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

      /* instruct user what is happening */
      if (!(cfg->ctrl & ARG_QUIET))
	{
	  r = pam_info(pamh, "Changing password for %s.", user);
	  if (r != PAM_SUCCESS)
	    return r;
	}

      /* If this is being run by root and we change a local password,
         we don't need to get the old password. */
      if (i_am_root)
	{
	  if (cfg->ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "process run by root, do nothing");
	  return PAM_SUCCESS;
        }

      /* don't ask for the old password if it is empty */
      if (is_blank_password(pw, sp))
	{
	  if (cfg->ctrl & ARG_DEBUG)
	    pam_syslog(pamh, LOG_DEBUG, "Old password is empty, skip");
	  return PAM_SUCCESS;
	}

      bool pwchangeable = true;
      r = expired_check(sp, NULL, &pwchangeable);
      if (!pwchangeable && !i_am_root)
	{
	  pam_error(pamh, "You must wait longer to change your password.");
	  return PAM_AUTHTOK_ERR;
	}
      pam_syslog(pamh, LOG_DEBUG, "expired_check=%i", r);
      if (r == PWA_EXPIRED_NO && (flags & PAM_CHANGE_EXPIRED_AUTHTOK))
	{
	  pam_error(pamh, "Password not expired");
	  return PAM_AUTHTOK_ERR;
	}

      r = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &pass_old, NULL);
      if (r != PAM_SUCCESS)
	{
	  pam_syslog(pamh, LOG_NOTICE, "password - old token not obtained");
	  return r;
	}

      r = authenticate_user(pamh, cfg->ctrl, user, pass_old, &authenticated, &error);
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
	      if (cfg->ctrl & ARG_DEBUG)
		pam_syslog(pamh, LOG_DEBUG, "%s - %s", no_new_pass_msg, pam_strerror(pamh, r));
	      pass_old = NULL;
	      return r;
	    }

	  if (isempty(pass_new) || (pass_old && streq(pass_new, pass_old)))
	    {
	      /* remove new password */
	      pam_set_item(pamh, PAM_AUTHTOK, NULL);
	      pass_new = NULL;
	      if (cfg->ctrl & ARG_DEBUG)
		pam_syslog(pamh, LOG_DEBUG, "%s", no_new_pass_msg);
	      pam_error(pamh, "%s.", no_new_pass_msg);
	      r = PAM_AUTHTOK_ERR;
	    }
	  else if (strlen(strempty(pass_new)) > PAM_MAX_RESP_SIZE)
	    {
	      /* remove new password */
	      pam_set_item(pamh, PAM_AUTHTOK, NULL);
	      pass_new = NULL;
	      pam_syslog(pamh, LOG_NOTICE, "supplied password to long");
	      pam_error(pamh, "You must choose a shorter password.");
	      r = PAM_AUTHTOK_ERR;
	    }
	  else if (strlen(strempty(pass_new)) < (size_t)cfg->minlen)
	    {
	      if (!i_am_root)
		{
		  /* remove new password */
		  pam_set_item(pamh, PAM_AUTHTOK, NULL);
		  pass_new = NULL;
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

      if (cfg->ctrl | ARG_DEBUG)
	pam_syslog(pamh, LOG_DEBUG, "Create hash with prefix=%s, count=%lu",
		   cfg->crypt_prefix, cfg->crypt_count);

      _cleanup_free_ char *error = NULL;
      char *new_hash = NULL;
      r = create_hash(pass_new, cfg->crypt_prefix, cfg->crypt_count,
		      &new_hash, &error);
      if (r < 0 || new_hash == NULL)
	{
	  if (r == -ENOMEM)
	    {
	      pam_syslog(pamh, LOG_CRIT, "Out of memory");
	      return PAM_BUF_ERR;
	    }
	  else
	    {
	      if (error)
		pam_syslog(pamh, LOG_ERR,
			   "crypt() failure: %s", error);
	      else
		pam_syslog(pamh, LOG_ERR, "crypt() failure for new password");
	    }
	  pass_new = pass_old = NULL; /* cleanup */
	  return PAM_SYSTEM_ERR;
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
  struct config_t cfg;
  int r;

  r = parse_args(pamh, flags, argc, argv, &cfg);
  if (r < 0)
    return errno_to_pam(r);

  if (cfg.ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &start);
      pam_syslog(pamh, LOG_DEBUG, "chauthtok called");
    }

  r = unix_chauthtok(pamh, flags, &cfg);

  if (cfg.ctrl & ARG_DEBUG)
    {
      clock_gettime(CLOCK_MONOTONIC, &stop);

      log_runtime_ms(pamh, "chauthtok", r, start, stop);
    }

  return r;
}
