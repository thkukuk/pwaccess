// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

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

#include "pwaccess.h"
#include "basics.h"
#include "mkdir_p.h"
#include "varlink-service-common.h"

#include "varlink-org.openSUSE.pwupd.h"

static bool
no_valid_name(const char *name)
{
  /* This function tests if the name has invalid characters, not if the
     name is really valid.

     User/group names must match BRE regex:
     [a-zA-Z0-9_.][a-zA-Z0-9_.-]*$\?

     Reject every name containing additional characters.
  */

  if (isempty(name))
    return true;

  while (*name != '\0')
    {
      if (!((*name >= 'a' && *name <= 'z') ||
	    (*name >= 'A' && *name <= 'Z') ||
	    (*name >= '0' && *name <= '9') ||
	    *name == '_' ||
	    *name == '.' ||
	    *name == '-' ||
	    *name == '$')
	  )
	return true;
      ++name;
    }

  return false;
}

static int
error_user_not_found(sd_varlink *link, int64_t uid, const char *name)
{
  if (errno == 0)
    {
      const char *cp;

      if (no_valid_name(name))
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

struct parameters {
  const char *pam_service;
  char *name;
  char *shell;
  char *response;
  sd_varlink *link;
};

static void
parameters_free(struct parameters *var)
{
  var->name = mfree(var->name);
  var->shell = mfree(var->shell);
  var->response = mfree(var->shell);
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
	  /* XXX NULL pointer check/calloc failed */
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
	  /* XXX check r */
	  sd_varlink_flush(p->link);
          break;
        default:
	  /* XXX error */
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
    .link = param->link,
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

  /* XXX check if shell is valid and really change it */
  log_msg(LOG_INFO, "chsh: changed shell for '%s' to '%s'", p.name, p.shell);

  return broadcast_and_return(r);
}

static pthread_t pam_thread;

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
    .link = link,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct parameters, name),  SD_JSON_MANDATORY},
    { "shell", SD_JSON_VARIANT_STRING,    sd_json_dispatch_string,  offsetof(struct parameters, shell), SD_JSON_MANDATORY},
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

  /* XXX verify that shell is allowed */

  r = pthread_create(&pam_thread, NULL, &run_pam_auth, &p);
  if (r != 0)
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "pthread_create failed: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

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
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "pthread_join failed: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
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

static void *
run_pam_chauthtok(void *arg)
{
  struct parameters *param = arg;
  _cleanup_(parameters_free) struct parameters p = {
    .pam_service = param->pam_service,
    .name = param->name,
    .shell = param->shell,
    .link = param->link,
  };
  const struct pam_conv conv = {
    varlink_conv,
    &p,
  };
  pam_handle_t *pamh = NULL;
  intptr_t r;
  int flags = 0;

#if 0
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
  r = pam_chauthtok(pamh, flags);
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
    .link = link,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct parameters, name),  SD_JSON_MANDATORY},
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
      log_msg(LOG_ERR, "chsh request: varlink dispatch failed: %s", strerror(-r));
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
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  /* Run under the UID of the caller, else pam_unix will not ask for old password */
  if (peer_uid != 0)
    {
      log_msg(LOG_DEBUG, "Callilng setuid(%u)", peer_uid);
      if (setuid(peer_uid) != 0)
	{ /* XXX move to function */
	  _cleanup_free_ char *error = NULL;

	  if (asprintf(&error, "setuid(%u) failed: %m", peer_uid) < 0)
	    error = NULL;
	  log_msg(LOG_ERR, "%s", stroom(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
	}
    }

  r = pthread_create(&pam_thread, NULL, &run_pam_chauthtok, &p);
  if (r != 0)
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "pthread_create failed: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

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
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "pthread_join failed: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
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
    .response = NULL,
    .link = link,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "response", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct parameters, response),  SD_JSON_MANDATORY},
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
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "No PAM thread running: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  r = sd_varlink_dispatch(p.link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "conv request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  /* set pam_response */
  pthread_mutex_lock(&mut);
  log_msg(LOG_DEBUG, "conv: set response and send cond_broadcast");
  if (send_v != NULL)
    sd_json_variant_unref(send_v);
  send_v = NULL;
  answer = strdup(p.response);
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
    { /* XXX move to function */
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "pthread_join failed: %s", strerror(r)) < 0)
        error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
  if (thread_res != PAM_SUCCESS)
    {
      _cleanup_free_ char *error = NULL;

      int64_t t = (int64_t)thread_res;
      if (asprintf(&error, "PAM authentication failed: %s", pam_strerror(NULL, t)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwupd.AuthenticationFailed",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
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
					  "org.openSUSE.pwupd.Chauthtok",      vl_method_chauthtok,
					  "org.openSUSE.pwupd.Chsh",           vl_method_chsh,
					  "org.openSUSE.pwupd.Conv",           vl_method_conv,
					  "org.openSUSE.pwupd.GetEnvironment", vl_method_get_environment,
					  "org.openSUSE.pwupd.Ping",           vl_method_ping,
					  "org.openSUSE.pwupd.Quit",           vl_method_quit,
					  "org.openSUSE.pwupd.SetLogLevel",    vl_method_set_log_level);
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
