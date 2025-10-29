// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libintl.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <pthread.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-journal.h>
#include <security/pam_appl.h>
#include <libeconf.h>

#include "pwaccess.h"
#include "basics.h"
#include "mkdir_p.h"
#include "varlink-service-common.h"
#include "files.h"
#include "verify.h"
#include "no_new_privs.h"
#include "chfn_checks.h"

#include "varlink-org.openSUSE.pwupd.h"

static int
error_user_not_found(sd_varlink *link, int64_t uid, const char *name)
{
  if (errno == 0)
    {
      const char *cp;

      if (!valid_name(name))
	cp = "<name contains invalid characters>";
      else
	cp = name;

      if (uid >= 0)
	log_msg(LOG_INFO, "User (%" PRId64 "|%s) not found", uid, strna(cp));
      else
	log_msg(LOG_INFO, "User '%s' not found", strna(cp));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.NoEntryFound",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
    }
  else
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "user not found: %m") < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
}

static int
return_errno_error(sd_varlink *link, const char *function, int r)
{
  _cleanup_free_ char *error = NULL;
  const char *varlink_error = "org.openSUSE.pwupd.InternalError";

  if (r < 0)
    r = -r;

  if (r == EPERM)
    varlink_error = "org.openSUSE.pwupd.PermissionDenied";

  if (asprintf(&error, "%s failed: %s", function, strerror(r)) < 0)
    error = NULL;
  log_msg(LOG_ERR, "%s", stroom(error));
  return sd_varlink_errorbo(link, varlink_error,
			    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
			    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
}


struct parameters {
  const char *pam_service;
  char *name;
  char *shell;
  char *full_name;
  char *home_phone;
  char *other;
  char *room;
  char *work_phone;
  char *old_gecos;
  char *response;
  int flags;
  sd_json_variant *content_passwd;
  sd_json_variant *content_shadow;
  /* run_as_user:
     0: let PAM module decide as what we run
     1: PAM modules should assume we run as user even if geteuid() returns 0 */
  int run_as_user;
  sd_varlink *link;
};

static void
parameters_free(struct parameters *var)
{
  var->name = mfree(var->name);
  var->shell = mfree(var->shell);
  var->full_name = mfree(var->full_name);
  var->home_phone = mfree(var->home_phone);
  var->other = mfree(var->other);
  var->room = mfree(var->room);
  var->work_phone = mfree(var->work_phone);
  var->old_gecos = mfree(var->old_gecos);
  var->response = mfree(var->response);
  var->content_passwd = sd_json_variant_unref(var->content_passwd);
  var->content_shadow = sd_json_variant_unref(var->content_shadow);
}

static sd_json_variant *send_v = NULL;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static char *answer = NULL;

static int
varlink_conv(int num_msg, const struct pam_message **msgm,
             struct pam_response **response, void *appdata_ptr)
{
  struct parameters *p = appdata_ptr;
  int r;

  log_msg(LOG_DEBUG, "varlink_conv with %i messages called", num_msg);

  assert(p);

  if (num_msg <= 0)
    return PAM_CONV_ERR;

  log_msg(LOG_DEBUG, "style=%i, msg=%s", msgm[0]->msg_style, msgm[0]->msg);

  for (int count = 0; count < num_msg; ++count)
    {
      switch (msgm[count]->msg_style)
        {
        case PAM_PROMPT_ECHO_ON:
        case PAM_PROMPT_ECHO_OFF:
	  pthread_mutex_lock(&mut);
	  if (send_v != NULL)
	    sd_json_variant_unref(send_v);
	  send_v = NULL;
	  r = sd_json_variant_merge_objectbo(&send_v,
					     SD_JSON_BUILD_PAIR_INTEGER("msg_style", msgm[count]->msg_style),
					     SD_JSON_BUILD_PAIR("message", SD_JSON_BUILD_STRING(msgm[count]->msg)));
	  if (r < 0)
	    log_msg(LOG_ERR, "Failed to build send_v list: %s\n", strerror(-r));
	  pthread_cond_broadcast(&cond);
	  pthread_mutex_unlock(&mut);

	  /* waiting for answer */
	  pthread_mutex_lock(&mut);
	  *response = calloc(num_msg, sizeof(struct pam_response));
	  if (*response == NULL)
	    {
	      log_msg(LOG_ERR, "Out of memory!");
	      pthread_mutex_unlock(&mut);
	      return PAM_BUF_ERR;
	    }
	  log_msg(LOG_DEBUG, "varlink_conv: calling pthread_cond_wait");
	  pthread_cond_wait(&cond, &mut);
	  response[0]->resp_retcode = 0;
	  response[0]->resp = answer;
	  pthread_mutex_unlock(&mut);
	  log_msg(LOG_DEBUG, "varlink_conv: after mutex");
          break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
	  r = sd_varlink_notifybo(p->link,
				  SD_JSON_BUILD_PAIR_INTEGER("msg_style", msgm[count]->msg_style),
				  SD_JSON_BUILD_PAIR("message", SD_JSON_BUILD_STRING(msgm[count]->msg)));
	  sd_varlink_flush(p->link);
	  if (r < 0)
	    {
	      log_msg(LOG_ERR, "Failed to send notify: %s\n", strerror(-r));
	      return PAM_SYSTEM_ERR;
	    }
          break;
        default:
	  log_msg(LOG_ERR, "Unknown msg style: %i\n", msgm[count]->msg_style);
	  return PAM_SYSTEM_ERR;
        }
    }

  return PAM_SUCCESS;
}

static void *
broadcast_and_return(intptr_t r)
{
  pthread_mutex_lock(&mut);
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&mut);

  return (void *)r;
}

static void *
run_pam_auth(void *arg)
{
  struct parameters *param = arg;
  _cleanup_(parameters_free) struct parameters p = {
    .pam_service = param->pam_service,
    .name = param->name,
    .shell = param->shell,
    .full_name = param->full_name,
    .home_phone = param->home_phone,
    .other = param->other,
    .room = param->room,
    .work_phone = param->work_phone,
    .old_gecos = param->old_gecos,
    .response = NULL,
    .flags = param->flags,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = param->link,
    .run_as_user = param->run_as_user,
  };
  const struct pam_conv conv = {
    varlink_conv,
    &p,
  };
  pam_handle_t *pamh = NULL;
  intptr_t r;

  r = pam_start(p.pam_service, p.name, &conv, &pamh);
  if (r != PAM_SUCCESS)
    {
      log_msg(LOG_ERR, "pam_start(\"%s\", %s) failed: %s", p.pam_service,
	      p.name, pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }

  if (p.run_as_user)
    {
      r = pam_putenv(pamh, "PAM_NO_ROOT=1");
      if (r != PAM_SUCCESS)
	{
	  log_msg(LOG_ERR, "pam_putenv(\"PAM_NO_ROOT=1\") failed: %s", pam_strerror(NULL, r));
	  return broadcast_and_return(r);
	}
    }

  r = pam_authenticate(pamh, 0);
  if (r != PAM_SUCCESS)
    {
      pam_end (pamh, r);
      log_msg(LOG_ERR, "pam_authenticate() failed: %s", pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }
  r = pam_acct_mgmt(pamh, 0);
  if (r == PAM_NEW_AUTHTOK_REQD)
    {
      r = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
      if (r != PAM_SUCCESS)
	{
	  pam_end (pamh, r);
	  log_msg(LOG_ERR, "pam_chauthtok() failed: %s", pam_strerror(NULL, r));
	  return broadcast_and_return(r);
	}
    }
  else if (r != PAM_SUCCESS)
    {
      pam_end (pamh, r);
      log_msg(LOG_ERR, "pam_acct_mgmt() failed: %s", pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }

  r = pam_end(pamh, 0);
  if (r != PAM_SUCCESS)
    {
      log_msg(LOG_ERR, "pam_end() failed: %s", pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }

  if (!isempty(p.shell))
    {
      struct passwd pw;

      memset(&pw, 0, sizeof(pw));
      pw.pw_name = p.name;
      pw.pw_shell = p.shell;
      r = update_passwd(&pw, NULL);
      if (r < 0)
	{
	  log_msg(LOG_ERR, "update_passwd() failed: %s", strerror(-r));
	  return broadcast_and_return(PAM_SYSTEM_ERR);
	}

      log_msg(LOG_INFO, "chsh: changed shell for '%s' to '%s'", p.name, p.shell);
    }
  else if (p.full_name || p.home_phone || p.other || p.room || p.work_phone)
    {
      const char *full_name = NULL;
      const char *home_phone = NULL;
      const char *other = NULL;
      const char *room = NULL;
      const char *work_phone = NULL;
      struct passwd pw;
      char *cp;
      const char *f;
      size_t s;
      _cleanup_free_ char *new_gecos = NULL;

      /* Split old GECOS field and overwrite single parts */
      cp = p.old_gecos;
      f = strsep(&cp, ",");
      full_name = f;
      f = strsep(&cp, ",");
      room = f;
      f = strsep(&cp, ",");
      work_phone = f;
      f = strsep(&cp, ",");
      home_phone = f;
      /* Anything left over is "other".  */
      other = cp;

      if (p.full_name != NULL)
	full_name = p.full_name;
      if (p.room != NULL)
	room = p.room;
      if (p.work_phone != NULL)
	work_phone = p.work_phone;
      if (p.home_phone != NULL)
	home_phone = p.home_phone;
      if (p.other)
	other = p.other;

      if (asprintf(&new_gecos, "%s,%s,%s,%s,%s",
		   strempty(full_name), strempty(room),
		   strempty(work_phone), strempty(home_phone),
		   strempty(other)) < 0)
	return broadcast_and_return(PAM_BUF_ERR);

      /* remove trailing ',' */
      s = strlen(new_gecos);
      while (s > 0 && new_gecos[s-1] == ',')
	{
	  new_gecos[s-1] = '\0';
	  s--;
	}

      memset(&pw, 0, sizeof(pw));
      pw.pw_name = p.name;
      pw.pw_gecos = new_gecos;
      r = update_passwd(&pw, NULL);
      if (r < 0)
	{
	  log_msg(LOG_ERR, "update_passwd() failed: %s", strerror(-r));
	  return broadcast_and_return(PAM_SYSTEM_ERR);
	}

      log_msg(LOG_INFO, "chfn: changed GECOS for '%s' to '%s'", p.name, strempty(new_gecos));
    }
  else
    log_msg(LOG_INFO, "chfn/chsh: nothing to update");

  return broadcast_and_return(PAM_SUCCESS);
}

static pthread_t pam_thread;

static int
vl_method_chfn(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  /* don't free via _cleanup_, can be still in use by the pam thread */
  struct parameters p = {
    .pam_service = "pwupd-chfn",
    .name = NULL,
    .shell = NULL,
    .full_name = NULL,
    .home_phone = NULL,
    .other = NULL,
    .room = NULL,
    .work_phone = NULL,
    .old_gecos = NULL,
    .response = NULL,
    .flags = 0,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = link,
    .run_as_user = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName",  SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, name),       SD_JSON_MANDATORY},
    { "fullName",  SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, full_name),  SD_JSON_NULLABLE},
    { "homePhone", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, home_phone), SD_JSON_NULLABLE},
    { "other",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, other),      SD_JSON_NULLABLE},
    { "room",      SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, room),       SD_JSON_NULLABLE},
    { "workPhone", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, work_phone), SD_JSON_NULLABLE},
    {}
  };
  _cleanup_free_ char *error = NULL;
  struct passwd *pw = NULL;
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"chfn\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "chfn request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.name))
    {
      parameters_free(&p);
      log_msg(LOG_ERR, "chfn request: no user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No user name specified"));
    }

  if (p.full_name)
    {
      if (!may_change_field(peer_uid, 'f'))
	{
	  parameters_free(&p);
	  return return_errno_error(link, "permission check (full name)", -EPERM);
	}
      if (!chfn_check_string(p.full_name, ":,=\n", &error))
	{
	  if (error)
	    log_msg(LOG_ERR, "chfn (full name): %s", error);
	  parameters_free(&p);
	  return return_errno_error(link, "character check (full name)", -EINVAL);
	}
    }
  if (p.home_phone)
    {
      if (!may_change_field(peer_uid, 'h'))
	{
	  parameters_free(&p);
	  return return_errno_error(link, "permission check (home phone)", -EPERM);
	}
      if (!chfn_check_string(p.home_phone, ":,=\n", &error))
	{
	  if (error)
	    log_msg(LOG_ERR, "chfn (home phone): %s", error);
	  parameters_free(&p);
	  return return_errno_error(link, "character check (home phone)", -EINVAL);
	}
    }
  if (p.other)
    {
      if (!may_change_field(peer_uid, 'o'))
	{
	  parameters_free(&p);
	  return return_errno_error(link, "permission check (other)", -EPERM);
	}
      if (!chfn_check_string(p.other, ":\n", &error))
	{
	  if (error)
	    log_msg(LOG_ERR, "chfn (other): %s", error);
	  parameters_free(&p);
	  return return_errno_error(link, "character check (other)", -EINVAL);
	}
    }
  if (p.room)
    {
      if (!may_change_field(peer_uid, 'r'))
	{
	  parameters_free(&p);
	  return return_errno_error(link, "permission check (room)", -EPERM);
	}
      if (!chfn_check_string(p.room, ":,=\n", &error))
	{
	  if (error)
	    log_msg(LOG_ERR, "chfn (room): %s", error);
	  parameters_free(&p);
	  return return_errno_error(link, "character check (room)", -EINVAL);
	}
    }
  if (p.work_phone)
    {
      if (!may_change_field(peer_uid, 'w'))
	{
	  parameters_free(&p);
	  return return_errno_error(link, "permission check (work phone)", -EPERM);
	}
      if (!chfn_check_string(p.work_phone, ":,=\n", &error))
	{
	  if (error)
	    log_msg(LOG_ERR, "chfn (work phone): %s", error);
	  parameters_free(&p);
	  return return_errno_error(link, "character check (work phone)", -EINVAL);
	}
    }

  errno = 0; /* to find out if getpwnam succeed and there is no entry or if there was an error */
  pw = getpwnam(p.name);
  if (pw == NULL)
    {
      r = error_user_not_found(link, -1, p.name);
      parameters_free(&p);
      return r;
    }

  p.old_gecos = strdup(strempty(pw->pw_gecos));
  if (p.old_gecos == NULL)
    {
      parameters_free(&p);
      return return_errno_error(link, "strdup", -ENOMEM);
    }

  /* Don't change GECOS if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      if (asprintf(&error, "Peer UID (%i) not 0 and peer UID not equal to UID",
		   peer_uid) < 0)
	error = NULL;
      log_msg(LOG_ERR, "chfn: %s", stroom(error));
      parameters_free(&p);
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  /* Run under the UID of the caller, else pam_unix will not ask for old password
     and pam_rootok will wrongly match. */
  /* XXX move in extra function */
  if (peer_uid != 0)
    {
      if (no_new_privs_enabled())
	{
	  log_msg(LOG_DEBUG, "NoNewPrivs is enabled, running PAM stack as root");
	  p.run_as_user = 1;
	}
      else
	{
	  log_msg(LOG_DEBUG, "Calling setresuid(%u,0,0)", peer_uid);
	  if (setresuid(peer_uid, 0, 0) != 0)
	    {
	      parameters_free(&p);
	      return return_errno_error(link, "setresuid", errno);
	    }
	}
    }

  r = pthread_create(&pam_thread, NULL, &run_pam_auth, &p);
  if (r != 0)
    return return_errno_error(link, "pthread_create", r);

  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "chfn: calling pthread_cond_wait");
  pthread_cond_wait(&cond, &mut);
  pthread_mutex_unlock(&mut);
  log_msg(LOG_DEBUG, "chfn: pthread_cond_wait succeeded");

  /* we need input from the user, quit method and send prompt back */
  if (send_v != NULL)
    return sd_varlink_reply(link, send_v);

  intptr_t *thread_res = NULL;
  r = pthread_join(pam_thread, (void **)&thread_res);
  if (r != 0)
    return return_errno_error(link, "pthread_join", r);

  if (thread_res != PAM_SUCCESS)
    {
      int64_t t = (int64_t)thread_res;
      if (t > 0)
	{
	  if (asprintf(&error, "PAM authentication failed: %s", pam_strerror(NULL, t)) < 0)
	    error = NULL;
	}
      else
	{
	  if (asprintf(&error, "Updating passwd/shadow failed: %s", strerror(-t)) < 0)
	    error = NULL;
	}

      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

/* XXX move all code access /etc/shells into one file */
static bool
is_known_shell(const char *shell)
{
  _cleanup_(econf_freeFilep) econf_file *key_file = NULL;
  _cleanup_(econf_freeArrayp) char **keys = NULL;
  size_t size = 0;
  econf_err error;

  error = econf_readConfig(&key_file,
                           NULL /* project */,
                           "/usr/etc" /* usr_conf_dir */,
                           "shells" /* config_name */,
                           NULL /* config_suffix */,
                           "" /* delim, key only */,
                           "#" /* comment */);
  if (error != ECONF_SUCCESS)
    {
      log_msg(LOG_ERR, "Cannot parse shell files: %s",
              econf_errString(error));
      return false;
    }

  error = econf_getKeys(key_file, NULL, &size, &keys);
  if (error)
    {
      log_msg(LOG_ERR, "Cannot evaluate entries in shell files: %s",
              econf_errString(error));
      return false;
    }

  for (size_t i = 0; i < size; i++)
    if (streq(keys[i], shell))
	return true;

  return false;
}

/* If the shell is completely invalid, print an error and
   return 1. If root changes the shell, print only a warning.
   Only exception: Invalid characters are always not allowed.  */
static int
check_shell(const char *shell, uid_t uid, char **msg)
{
  if (*shell != '/')
    {
      if (msg)
	*msg = strdup("Shell must be a full path name.");
      if (uid)
        return 1;
    }
  if (access (shell, F_OK) < 0)
    {
      if (msg)
	{
	  if (asprintf(msg, "'%s' does not exist.", shell) < 0)
	    *msg = NULL;
	}
      if (uid)
        return 1;
    }
  if (access (shell, X_OK) < 0)
    {
      if (msg)
	{
	  if (asprintf(msg, "'%s' is not executable.", shell) < 0)
	    *msg = NULL;
	}
      if (uid)
        return 1;
    }

  /* keep /etc/passwd clean. */
  for (size_t i = 0; i < strlen(shell); i++)
    {
      char c = shell[i];
      if (c == ',' || c == ':' || c == '=' || c == '"' || c == '\n')
        {
	  if (msg)
	    {
	      if (asprintf(msg, "'%c' is not allowed.", c) < 0)
		*msg = NULL;
	    }
          return 1;
        }
      if (iscntrl (c))
        {
          if (msg)
	    *msg = strdup("Control characters are not allowed.");
          return 1;
        }
    }

  if (!is_known_shell(shell))
    {
      if (msg)
	{
	  if (asprintf(msg, "%s: '%s' is not listed as valid login shell.", uid?"Error":"Warning", shell) < 0)
	    *msg = NULL;
	}
      if (uid)
	return 1;
    }
  return 0;
}

static int
vl_method_chsh(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  /* don't free, can be still in use by the pam thread */
  struct parameters p = {
    .pam_service = "pwupd-chsh",
    .name = NULL,
    .shell = NULL,
    .full_name = NULL,
    .home_phone = NULL,
    .other = NULL,
    .room = NULL,
    .work_phone = NULL,
    .old_gecos = NULL,
    .response = NULL,
    .flags = 0,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = link,
    .run_as_user = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, name),  SD_JSON_MANDATORY},
    { "shell",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, shell), SD_JSON_MANDATORY},
    { "flags",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,    offsetof(struct parameters, flags), 0},
    {}
  };
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"chsh\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "chsh request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.name))
    {
      log_msg(LOG_ERR, "chsh request: no user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No user name specified"));
    }

  struct passwd *pw = NULL;
  errno = 0; /* to find out if getpwnam succeed and there is no entry or if there was an error */
  pw = getpwnam(p.name);

  if (pw == NULL) /* XXX manual free p */
    return error_user_not_found(link, -1, p.name);

  /* Don't change shell if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "Peer UID (%i) not 0 and peer UID not equal to UID",
		   peer_uid) < 0)
	error = NULL;
      log_msg(LOG_ERR, "chsh: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  _cleanup_free_ char *msg = NULL;
  r = check_shell(p.shell, peer_uid, &msg);
  if (r != 0)
    {
      log_msg(LOG_ERR, "chsh (check_shell): %s", stroom(msg));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InvalidShell",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(msg)));
    }
  if (msg)
    {
      /* XXX send msg as informal text */
    }

  /* Run under the UID of the caller, else pam_unix will not ask for old password
     and pam_rootok will wrongly match. */
  /* XXX move in extra function */
  if (peer_uid != 0)
    {
      if (no_new_privs_enabled())
	{
	  log_msg(LOG_DEBUG, "NoNewPrivs is enabled, running PAM stack as root");
	  p.run_as_user = 1;
	}
      else
	{
	  log_msg(LOG_DEBUG, "Calling setresuid(%u,0,0)", peer_uid);
	  if (setresuid(peer_uid, 0, 0) != 0)
	    return return_errno_error(link, "setresuid", errno);
	}
    }

  r = pthread_create(&pam_thread, NULL, &run_pam_auth, &p);
  if (r != 0)
    return return_errno_error(link, "pthread_create", r);

  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "chsh: calling pthread_cond_wait");
  pthread_cond_wait(&cond, &mut);
  pthread_mutex_unlock(&mut);
  log_msg(LOG_DEBUG, "chsh: pthread_cond_wait succeeded");

  /* we need input from the user, quit method and send prompt back */
  if (send_v != NULL)
    return sd_varlink_reply(link, send_v);

  intptr_t *thread_res = NULL;
  r = pthread_join(pam_thread, (void **)&thread_res);
  if (r != 0)
    return return_errno_error(link, "pthread_join", r);

  if (thread_res != PAM_SUCCESS)
    {
      _cleanup_free_ char *error = NULL;

      int64_t t = (int64_t)thread_res;
      if (t > 0)
	{
	  if (asprintf(&error, "PAM authentication failed: %s", pam_strerror(NULL, t)) < 0)
	    error = NULL;
	}
      else
	{
	  if (asprintf(&error, "Updating passwd/shadow failed: %s", strerror(-t)) < 0)
	    error = NULL;
	}

      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static void *
run_pam_chauthtok(void *arg)
{
  struct parameters *param = arg;
  _cleanup_(parameters_free) struct parameters p = {
    .pam_service = param->pam_service,
    .name = param->name,
    .shell = param->shell,
    .full_name = param->full_name,
    .home_phone = param->home_phone,
    .other = param->other,
    .room = param->room,
    .work_phone = param->work_phone,
    .old_gecos = param->old_gecos,
    .response = NULL,
    .flags = param->flags,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = param->link,
    .run_as_user = param->run_as_user,
  };
  const struct pam_conv conv = {
    varlink_conv,
    &p,
  };
  pam_handle_t *pamh = NULL;
  intptr_t r;

#if 0 /* XXX */
  if (silent)
    flags |= PAM_SILENT;
  if (change_expired)
    flags |= PAM_CHANGE_EXPIRED_AUTHTOK;
#endif

  r = pam_start(p.pam_service, p.name, &conv, &pamh);
  if (r != PAM_SUCCESS)
    {
      log_msg(LOG_ERR, "pam_start(\"%s\", %s) failed: %s", p.pam_service,
	      p.name, pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }

  if (p.run_as_user)
    {
      r = pam_putenv(pamh, "PAM_NO_ROOT=1");
      if (r != PAM_SUCCESS)
	{
	  log_msg(LOG_ERR, "pam_putenv(\"PAM_NO_ROOT=1\") failed: %s", pam_strerror(NULL, r));
	  return broadcast_and_return(r);
	}
    }

  log_msg(LOG_DEBUG, "pam_chauthok(pamh, %i)", p.flags);
  r = pam_chauthtok(pamh, p.flags);
  if (r != PAM_SUCCESS)
    {
      pam_end (pamh, r);
      log_msg(LOG_ERR, "pam_chauthtok() failed: %s", pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }
  r = pam_end(pamh, 0);
  if (r != PAM_SUCCESS)
    {
      log_msg(LOG_ERR, "pam_end() failed: %s", pam_strerror(NULL, r));
      return broadcast_and_return(r);
    }

  return broadcast_and_return(r);
}

static int
vl_method_chauthtok(sd_varlink *link, sd_json_variant *parameters,
		    sd_varlink_method_flags_t _unused_(flags),
		    void _unused_(*userdata))
{
  /* don't free, can be still in use by the pam thread */
  struct parameters p = {
    .pam_service = "pwupd-passwd",
    .name = NULL,
    .shell = NULL,
    .full_name = NULL,
    .home_phone = NULL,
    .other = NULL,
    .room = NULL,
    .work_phone = NULL,
    .old_gecos = NULL,
    .response = NULL,
    .flags = 0,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = link,
    .run_as_user = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, name),  SD_JSON_MANDATORY},
    { "flags",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,    offsetof(struct parameters, flags), 0},
    {}
  };
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"chauthtok\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "chauthtok: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.name))
    {
      log_msg(LOG_ERR, "chauthtok request: no user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No user name specified"));
    }

  struct passwd *pw = NULL;
  errno = 0; /* to find out if getpwnam succeed and there is no entry or if there was an error */
  pw = getpwnam(p.name);

  if (pw == NULL) /* XXX manual free p */
    return error_user_not_found(link, -1, p.name);

  /* Don't change password if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "Peer UID (%i) not 0 and peer UID not equal to UID",
		   peer_uid) < 0)
	error = NULL;
      log_msg(LOG_ERR, "chauthtok: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.PermissionDenied",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  /* Run under the UID of the caller, else pam_unix will not ask for old password
     and pam_rootok will wrongly match. */
  /* XXX move in extra function */
  if (peer_uid != 0)
    {
      if (no_new_privs_enabled())
	{
	  log_msg(LOG_DEBUG, "NoNewPrivs is enabled, running PAM stack as root");
	  p.run_as_user = 1;
	}
      else
	{
	  log_msg(LOG_DEBUG, "Calling setresuid(%u,0,0)", peer_uid);
	  if (setresuid(peer_uid, 0, 0) != 0)
	    return return_errno_error(link, "setresuid", errno);
	}
    }

  r = pthread_create(&pam_thread, NULL, &run_pam_chauthtok, &p);
  if (r != 0)
    return return_errno_error(link, "pthread_create", errno);

  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "chauthtok: calling pthread_cond_wait");
  pthread_cond_wait(&cond, &mut);
  pthread_mutex_unlock(&mut);
  log_msg(LOG_DEBUG, "chauthtok: pthread_cond_wait succeeded");

  /* we need input from the user, quit method and send prompt back */
  if (send_v != NULL)
    return sd_varlink_reply(link, send_v);

  intptr_t *thread_res = NULL;
  r = pthread_join(pam_thread, (void **)&thread_res);
  if (r != 0)
    return return_errno_error(link, "pthread_joind", errno);

  if (thread_res != PAM_SUCCESS)
    {
      _cleanup_free_ char *error = NULL;

      int64_t t = (int64_t)thread_res;
      if (asprintf(&error, "PAM authentication failed: %s", pam_strerror(NULL, t)) < 0)
	error = NULL;
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static int
vl_method_conv(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  _cleanup_(parameters_free) struct parameters p = {
    .name = NULL,
    .shell = NULL,
    .full_name = NULL,
    .home_phone = NULL,
    .other = NULL,
    .room = NULL,
    .work_phone = NULL,
    .old_gecos = NULL,
    .response = NULL,
    .flags = 0,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = link,
    .run_as_user = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "response", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct parameters, response),  SD_JSON_NULLABLE},
    {}
  };
  int r;

  log_msg(LOG_INFO, "Varlink method \"conv\" called...");

  /* make sure there is a pam_start() thread running! */
  if (pam_thread != 0)
    r = pthread_kill(pam_thread, 0);
  else
    r = ENOENT;
  if (r != 0)
    return return_errno_error(link, "Finding PAM thread", r);

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Conv request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  /* set pam_response */
  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "conv: set response and send cond_broadcast");
  if (send_v != NULL)
    sd_json_variant_unref(send_v);
  send_v = NULL;
  if (p.response)
    answer = strdup(p.response);
  else
    answer = NULL;
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&mut);

  /* wait for next PAM_PROMPT_ECHO_* message or exit */
  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "conv: calling pthread_cond_wait");
  pthread_cond_wait(&cond, &mut);
  pthread_mutex_unlock(&mut);
  log_msg(LOG_DEBUG, "conv: pthread_cond_wait succeeded");

  /* we need input from the user, quit method and send prompt back */
  if (send_v != NULL)
    return sd_varlink_reply(link, send_v);

  intptr_t *thread_res = NULL;
  r = pthread_join(pam_thread, (void **)&thread_res);
  if (r != 0)
    return return_errno_error(link, "pthread_join", r);

  if (thread_res != PAM_SUCCESS)
    {
      _cleanup_free_ char *error = NULL;

      int64_t t = (int64_t)thread_res;
      if (asprintf(&error, "Password change aborted: %s", pam_strerror(NULL, t)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.PasswordChangeAborted",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static int
vl_method_update_pw_sp(sd_varlink *link, sd_json_variant *parameters,
		       sd_varlink_method_flags_t _unused_(flags),
		       void _unused_(*userdata))
{
  _cleanup_(parameters_free) struct parameters p = {
    .name = NULL,
    .shell = NULL,
    .full_name = NULL,
    .home_phone = NULL,
    .other = NULL,
    .room = NULL,
    .work_phone = NULL,
    .old_gecos = NULL,
    .response = NULL,
    .flags = 0,
    .content_passwd = NULL,
    .content_shadow = NULL,
    .link = link,
    .run_as_user = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "passwd",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct parameters, content_passwd), SD_JSON_NULLABLE },
    { "shadow",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct parameters, content_shadow), SD_JSON_NULLABLE },
    {}
  };
  static const sd_json_dispatch_field dispatch_passwd_table[] = {
    { "name",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_name),   SD_JSON_MANDATORY },
    { "passwd", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_passwd), SD_JSON_NULLABLE },
    { "UID",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,   offsetof(struct passwd, pw_uid),    SD_JSON_MANDATORY },
    { "GID",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,   offsetof(struct passwd, pw_gid),    SD_JSON_MANDATORY },
    { "GECOS",  SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_gecos),  SD_JSON_NULLABLE },
    { "dir",    SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_dir),    SD_JSON_NULLABLE },
    { "shell",  SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_shell),  SD_JSON_NULLABLE },
    {}
  };
  static const sd_json_dispatch_field dispatch_shadow_table[] = {
    { "name",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct spwd, sp_namp),   SD_JSON_MANDATORY },
    { "passwd", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct spwd, sp_pwdp),   SD_JSON_NULLABLE },
    { "lstchg", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_lstchg), 0 },
    { "min",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_min),    0 },
    { "max",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_max),    0 },
    { "warn",   SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_warn),   0 },
    { "inact",  SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_inact),  0 },
    { "expire", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_expire), 0 },
    { "flag",   SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct spwd, sp_flag),   0 },
    {}
  };
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"UpdatePasswdShadow\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    return return_errno_error(link, "Get peer UID", r);

  if (peer_uid != 0)
    return return_errno_error(link, "UpdatePasswdShadow", -EPERM);

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    return return_errno_error(link, "UpdatePasswdShadow - varlink dispatch", r);

  if (sd_json_variant_is_null(p.content_passwd))
    {
      log_msg(LOG_ERR, "UpdatePasswdShadow request: no entry found\n");
      return 0;
    }

  pw = calloc(1, sizeof(struct passwd));
  if (pw == NULL)
    return -ENOMEM;

  r = sd_json_dispatch(p.content_passwd, dispatch_passwd_table, SD_JSON_ALLOW_EXTENSIONS, pw);
  if (r < 0)
    return return_errno_error(link, "Parsing JSON passwd entry", r);

  if (!sd_json_variant_is_null(p.content_shadow) && sd_json_variant_elements(p.content_shadow) > 0)
    {
      sp = calloc(1, sizeof(struct spwd));
      if (sp == NULL)
        return -ENOMEM;

      r = sd_json_dispatch(p.content_shadow, dispatch_shadow_table, SD_JSON_ALLOW_EXTENSIONS, sp);
      if (r < 0)
	return return_errno_error(link, "Parsing JSON shadow entry", r);
    }

  /* XXX check that pw->pw_name and sp->sp_namp are identical if both
     are provided */

  r = update_passwd(pw, NULL);
  if (r < 0)
    return return_errno_error(link, "Update of passwd", r);

  if (sp)
    {
      r = update_shadow(sp, NULL);
      if (r < 0)
	return return_errno_error(link, "Update of shadow", r);
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static int
run_varlink (void)
{
  int r;
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;

  r = mkdir_p(_VARLINK_PWUPD_SOCKET_DIR, 0755);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create directory '"_VARLINK_PWUPD_SOCKET_DIR"' for Varlink socket: %s",
	      strerror(-r));
      return r;
    }

  r = sd_varlink_server_new (&varlink_server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_INPUT_SENSITIVE);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to allocate varlink server: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_description (varlink_server, "pwupdd");
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to set varlink server description: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_info (varlink_server, NULL, PACKAGE" (pwupdd)",
				  VERSION, "https://github.com/thkukuk/pwaccess");
  if (r < 0)
    return r;

  r = sd_varlink_server_add_interface (varlink_server, &vl_interface_org_openSUSE_pwupd);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to add interface: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_bind_method_many (varlink_server,
					  "org.openSUSE.pwupd.Chauthtok",          vl_method_chauthtok,
					  "org.openSUSE.pwupd.Chfn",               vl_method_chfn,
					  "org.openSUSE.pwupd.Chsh",               vl_method_chsh,
					  "org.openSUSE.pwupd.Conv",               vl_method_conv,
					  "org.openSUSE.pwupd.UpdatePasswdShadow", vl_method_update_pw_sp,
					  "org.openSUSE.pwupd.GetEnvironment",     vl_method_get_environment,
					  "org.openSUSE.pwupd.Ping",               vl_method_ping,
					  "org.openSUSE.pwupd.Quit",               vl_method_quit,
					  "org.openSUSE.pwupd.SetLogLevel",        vl_method_set_log_level);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind Varlink methods: %s",
	      strerror(-r));
      return r;
    }


  r = sd_varlink_server_loop_auto(varlink_server);
  if (r == -EPERM)
    {
      log_msg(LOG_ERR, "Invoked by unprivileged Varlink peer, refusing.");
      return r;
    }
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to run Varlink event loop: %s",
	      strerror(-r));
      return r;
    }

  return 0;
}

static void
print_help (void)
{
  printf("pwupd - manage updating passwd and shadow entries\n");

  printf("  -d, --debug    Debug mode\n");
  printf("  -v, --verbose  Verbose logging\n");
  printf("  -?, --help     Give this help list\n");
  printf("      --version  Print program version\n");
}

int
main (int argc, char **argv)
{
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"socket", no_argument, NULL, 's'},
          {"debug", no_argument, NULL, 'd'},
          {"verbose", no_argument, NULL, 'v'},
          {"version", no_argument, NULL, '\255'},
          {"usage", no_argument, NULL, '?'},
          {"help", no_argument, NULL, 'h'},
          {NULL, 0, NULL, '\0'}
        };


      c = getopt_long (argc, argv, "sdvh?", long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'd':
	  set_max_log_level(LOG_DEBUG);
          break;
        case '?':
        case 'h':
          print_help ();
          return 0;
        case 'v':
	  set_max_log_level(LOG_INFO);
          break;
        case '\255':
          fprintf (stdout, "pwupdd (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_help ();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf (stderr, "Try `pwupdd --help' for more information.\n");
      return 1;
    }

  log_msg (LOG_INFO, "Starting pwupdd (%s) %s...", PACKAGE, VERSION);

  int r = run_varlink ();
  if (r < 0)
    return -r;

  log_msg (LOG_INFO, "pwupdd stopped.");

  return 0;
}
