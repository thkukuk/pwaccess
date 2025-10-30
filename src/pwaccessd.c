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
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-journal.h>

#include "pwaccess.h"
#include "basics.h"
#include "mkdir_p.h"
#include "verify.h"
#include "varlink-service-common.h"

#include "varlink-org.openSUSE.pwaccess.h"

#define USEC_PER_SEC  ((uint64_t) 1000000ULL)
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

static int socket_activation = false;

static int
error_user_not_found(sd_varlink *link, int64_t uid, const char *name, int errcode)
{
  if (errcode == 0)
    {
      if (uid >= 0)
	log_msg(LOG_INFO, "User (%" PRId64 ") not found", uid);
      else
	{
	  const char *cp;

	  if (!valid_name(name))
	    cp = "<name contains invalid characters>";
	  else
	    cp = name;

	  log_msg(LOG_INFO, "User '%s' not found", strna(cp));
	}
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.NoEntryFound",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
    }
  else
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "user not found: %s", strerror(errcode)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
}


struct parameters {
  int64_t uid;
  char *name;
  char *password;
  bool nullok;
};

static void
parameters_free(struct parameters *var)
{
  var->name = mfree(var->name);
  if (var->password)
    {
      explicit_bzero(var->password, strlen(var->password));
      var->password = mfree(var->password);
    }
}

static int
vl_method_get_account_name(sd_varlink *link, sd_json_variant *parameters,
			   sd_varlink_method_flags_t _unused_(flags),
			   void _unused_(*userdata))
{
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
  _cleanup_(parameters_free) struct parameters p = {
    .uid = -1,
    .name = NULL,
    .password = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "uid",      SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,  offsetof(struct parameters, uid), SD_JSON_MANDATORY},
    {}
  };
  struct passwd *pw = NULL;
  int r;

  log_msg(LOG_INFO, "Varlink method \"GetAccountName\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "GetAccountName request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  log_msg(LOG_DEBUG, "GetAccountName(%" PRId64 ")", p.uid);

  if (p.uid == -1)
    {
      log_msg(LOG_ERR, "GetAccountName request: no UID specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No UID specified"));
    }

  errno = 0; /* to find out if getpwuid succeed and there is no entry if there was an error */
  pw = getpwuid(p.uid);
  if (pw == NULL)
    return error_user_not_found(link, p.uid, NULL, errno);

  return sd_varlink_replybo(link,
                            SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
                            SD_JSON_BUILD_PAIR_STRING("userName", pw->pw_name));
}

static int
vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters,
			  sd_varlink_method_flags_t _unused_(flags),
			  void _unused_(*userdata))
{
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *passwd = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *shadow = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
  _cleanup_(parameters_free) struct parameters p = {
    .uid = -1,
    .name = NULL,
    .password = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "uid",      SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,  offsetof(struct parameters, uid), 0},
    { "userName", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct parameters, name), 0},
    {}
  };
  struct passwd *pw = NULL;
  struct spwd *sp = NULL;
  bool complete = true;
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"GetUserRecord\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "GetUserRecord request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  log_msg(LOG_DEBUG, "GetUserRecord(%" PRId64 ",%s)", p.uid, strna(p.name));

  if (p.uid == -1 && isempty(p.name))
    {
      log_msg(LOG_ERR, "GetUserRecord request: no UID nor user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No UID nor user name specified"));
    }
  if (p.uid != -1 && !isempty(p.name))
    {
      log_msg(LOG_ERR, "GetUserRecord request: UID and user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "UID and user name specified"));
    }

  errno = 0; /* to find out if getpwuid/getpwnam succeed and there is no
		entry if there was an error */
  if (p.uid != -1)
    pw = getpwuid(p.uid);
  else
    pw = getpwnam(p.name);
  if (pw == NULL)
    return error_user_not_found(link, p.uid, p.name, errno);

  /* Don't return password if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      log_msg(LOG_DEBUG, "GetUserRecord: peer UID not 0 and UID not equal to peer UID (%i,%i)",
	      peer_uid, pw->pw_uid);
      pw->pw_passwd = NULL;
      complete = false;
      /* no shadow entries for others */
      sp = NULL;
    }
  else
    {
      /* Get shadow entry */
      errno = 0;
      sp = getspnam(pw->pw_name);
      if (sp == NULL && errno != 0)
	{
	  _cleanup_free_ char *error = NULL;

	  if (asprintf(&error, "getspnam() failed: %m") < 0)
	    error = NULL;
	  log_msg(LOG_ERR, "%s", stroom(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
	}
    }

  r = sd_json_variant_merge_objectbo(&passwd,
				     SD_JSON_BUILD_PAIR_STRING("name", pw->pw_name),
				     SD_JSON_BUILD_PAIR_STRING("passwd", pw->pw_passwd),
				     SD_JSON_BUILD_PAIR_INTEGER("UID", pw->pw_uid),
				     SD_JSON_BUILD_PAIR_INTEGER("GID", pw->pw_gid),
				     SD_JSON_BUILD_PAIR_STRING("GECOS", pw->pw_gecos),
				     SD_JSON_BUILD_PAIR_STRING("dir", pw->pw_dir),
				     SD_JSON_BUILD_PAIR_STRING("shell", pw->pw_shell));
  if (r < 0)
    {
      _cleanup_free_ char *error = NULL;
      if (asprintf(&error, "JSON merge object passwd failed: %s",
		   strerror(-r)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  if (sp)
    {
      r = sd_json_variant_merge_objectbo(&shadow,
					 SD_JSON_BUILD_PAIR_STRING("name", sp->sp_namp),
					 SD_JSON_BUILD_PAIR_STRING("passwd", sp->sp_pwdp),
					 SD_JSON_BUILD_PAIR_INTEGER("lstchg", sp->sp_lstchg),
					 SD_JSON_BUILD_PAIR_INTEGER("min", sp->sp_min),
					 SD_JSON_BUILD_PAIR_INTEGER("max", sp->sp_max),
					 SD_JSON_BUILD_PAIR_INTEGER("warn", sp->sp_warn),
					 SD_JSON_BUILD_PAIR_INTEGER("inact", sp->sp_inact),
					 SD_JSON_BUILD_PAIR_INTEGER("expire", sp->sp_expire),
					 SD_JSON_BUILD_PAIR_INTEGER("flag", sp->sp_flag));
      if (r < 0)
	{
	  _cleanup_free_ char *error = NULL;
	  if (asprintf(&error, "JSON merge object shadow failed: %s",
		       strerror(-r)) < 0)
	    error = NULL;
	  log_msg(LOG_ERR, "%s", stroom(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
	}
    }

  r = sd_json_variant_merge_objectbo(&result, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
  if (r >= 0 && (passwd || shadow))
    r = sd_json_variant_merge_objectbo(&result, SD_JSON_BUILD_PAIR_BOOLEAN("Complete", complete));
  if (r >= 0 && passwd)
    r = sd_json_variant_merge_objectbo(&result, SD_JSON_BUILD_PAIR_VARIANT("passwd", passwd));
  if (r >= 0 && shadow)
    r = sd_json_variant_merge_objectbo(&result, SD_JSON_BUILD_PAIR_VARIANT("shadow", shadow));
  if (r < 0)
    {
      _cleanup_free_ char *error = NULL;
      if (asprintf(&error, "JSON merge result object failed: %s",
		   strerror(-r)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "%s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  return sd_varlink_reply(link, result);
}

static int
vl_method_verify_password(sd_varlink *link, sd_json_variant *parameters,
			  sd_varlink_method_flags_t _unused_(flags),
			  void _unused_(*userdata))
{
  _cleanup_(parameters_free) struct parameters p = {
    .name = NULL,
    .password = NULL,
    .nullok = false
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct parameters, name),     SD_JSON_MANDATORY},
    { "password", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct parameters, password), SD_JSON_MANDATORY},
    { "nullOK",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct parameters, nullok),   0},
    {}
  };
  uid_t peer_uid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"VerifyPassword\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "VerifyPassword request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.name))
    {
      log_msg(LOG_ERR, "VerifyPassword request: no user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No user name specified"));
    }

  struct passwd *pw = NULL;
  errno = 0; /* to find out if getpwnam succeed and there is no entry or if there was an error */
  pw = getpwnam(p.name);
  if (pw == NULL)
    return error_user_not_found(link, -1, p.name, errno);

  /* Don't verify password if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "Peer UID (%i) not 0 and peer UID not equal to UID",
		   peer_uid) < 0)
	error = NULL;
      log_msg(LOG_ERR, "VerifyPassword: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  const char *hash = NULL;
  if (is_shadow(pw))
    {
      /* Get shadow entry */
      errno = 0;
      struct spwd *sp = getspnam(pw->pw_name);
      if (sp == NULL && errno != 0)
	{
	  _cleanup_free_ char *error = NULL;

	  if (asprintf(&error, "getspnam() failed: %m") < 0)
	    error = NULL;
	  log_msg(LOG_ERR, "%s", stroom(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
	}
      hash = sp->sp_pwdp;
    }
  else
    hash = pw->pw_passwd;

  r = verify_password(hash, p.password, p.nullok);
  if (r < 0)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "verify_password() failed: %s", strerror(-r)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "verify_password: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }
  else if (r > 0)
    {
      if (r == VERIFY_FAILED) /* password does not match */
	{
	  log_msg(LOG_DEBUG, "verify_password (%s): password does not match", strna(pw->pw_name));
	  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
	}
      else /* libcrypt/internal error */
	{
	  const char *error = NULL;

	  if (r == VERIFY_CRYPT_DISABLED)
	    error = "The used salt is disabled in libcrypt";
	  else if (r == VERIFY_CRYPT_INVALID)
	    error = "The used salt is not supported by libcrypt";

	  log_msg(LOG_ERR, "verify_password failed: %s", strna(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", strna(error)));
	}
    }

  log_msg(LOG_DEBUG, "verify_password (%s): password matches", strna(pw->pw_name));
  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static int
vl_method_expired_check(sd_varlink *link, sd_json_variant *parameters,
			sd_varlink_method_flags_t _unused_(flags),
			void _unused_(*userdata))
{
  _cleanup_(parameters_free) struct parameters p = {
    .name = NULL,
    .password = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "userName", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct parameters, name), SD_JSON_MANDATORY},
    {}
  };
  uid_t peer_uid;
  long daysleft;
  bool pwchangeable;
  int r;

  log_msg(LOG_INFO, "Varlink method \"ExpiredCheck\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "ExpiredCheck request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.name))
    {
      log_msg(LOG_ERR, "ExpiredCheck request: no user name specified");
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No user name specified"));
    }

  struct passwd *pw;
  errno = 0; /* to find out if getpwnam succeed and there is no entry or if there was an error */
  pw = getpwnam(p.name);
  if (pw == NULL)
    return error_user_not_found(link, -1, p.name, errno);

  /* Don't verify password if query does not come from root
     and result is not the one of the calling user */
  if (peer_uid != 0 && pw->pw_uid != peer_uid)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "Peer UID (%i) not 0 and peer UID not equal to UID",
		   peer_uid) < 0)
	error = NULL;
      log_msg(LOG_ERR, "ExpiredCheck: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  /* Get shadow entry */
  errno = 0;
  struct spwd *sp = getspnam(pw->pw_name);
  if (sp == NULL)
    {
      if (errno != 0)
	{
	  _cleanup_free_ char *error = NULL;

	  if (asprintf(&error, "getspnam() failed: %m") < 0)
	    error = NULL;
	  log_msg(LOG_ERR, "%s", stroom(error));
	  return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
	}
      log_msg(LOG_DEBUG, "ExpiredCheck: no shadow entry for %s", pw->pw_name);
      return sd_varlink_replybo(link,
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
				SD_JSON_BUILD_PAIR_INTEGER("Expired", PWA_EXPIRED_NO));
    }

  r = expired_check(sp, &daysleft, &pwchangeable);
  if (r < 0)
    {
      _cleanup_free_ char *error = NULL;

      if (asprintf(&error, "expired_check() failed: %s", strerror(-r)) < 0)
	error = NULL;
      log_msg(LOG_ERR, "expired_check: %s", stroom(error));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", stroom(error)));
    }

  log_msg(LOG_DEBUG, "expired_check(%s): expired: %d, daysleft: %ld", strna(p.name), r, daysleft);
  return sd_varlink_replybo(link,
			    SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
			    SD_JSON_BUILD_PAIR_INTEGER("DaysLeft", daysleft),
			    SD_JSON_BUILD_PAIR_INTEGER("Expired", r),
			    SD_JSON_BUILD_PAIR_BOOLEAN("PWChangeAble", pwchangeable));
}

/* Send a messages to systemd daemon, that inicialization of daemon
   is finished and daemon is ready to accept connections. */
static void
announce_ready (void)
{
  int r = sd_notify (0, "READY=1\n"
		     "STATUS=Processing requests...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(READY) failed: %s", strerror(-r));
}

static void
announce_stopping (void)
{
  int r = sd_notify (0, "STOPPING=1\n"
		     "STATUS=Shutting down...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(STOPPING) failed: %s", strerror(-r));
}

/* event loop which quits after 30 seconds idle time */
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

static int
varlink_event_loop_with_idle(sd_event *e, sd_varlink_server *s)
{
  int r, code;

  for (;;)
    {
      r = sd_event_get_state(e);
      if (r < 0)
	return r;
      if (r == SD_EVENT_FINISHED)
	break;

      r = sd_event_run(e, DEFAULT_EXIT_USEC);
      if (r < 0)
	return r;

      if (r == 0 && (sd_varlink_server_current_connections(s) == 0))
	sd_event_exit(e, 0);
    }

  r = sd_event_get_exit_code(e, &code);
  if (r < 0)
    return r;

  return code;
}

static int
run_varlink (void)
{
  int r;
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;

  r = mkdir_p(_VARLINK_PWACCESS_SOCKET_DIR, 0755);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create directory '"_VARLINK_PWACCESS_SOCKET_DIR"' for Varlink socket: %s",
	      strerror(-r));
      return r;
    }

  r = sd_event_new (&event);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to create new event: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_new (&varlink_server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_INPUT_SENSITIVE);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to allocate varlink server: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_description (varlink_server, "pwaccessd");
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to set varlink server description: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_info (varlink_server, NULL, PACKAGE" (pwaccessd)",
				  VERSION, "https://github.com/thkukuk/pwaccess");
  if (r < 0)
    return r;

  r = sd_varlink_server_add_interface (varlink_server, &vl_interface_org_openSUSE_pwaccess);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to add interface: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_bind_method_many (varlink_server,
					  "org.openSUSE.pwaccess.GetAccountName", vl_method_get_account_name,
					  "org.openSUSE.pwaccess.GetUserRecord",  vl_method_get_user_record,
					  "org.openSUSE.pwaccess.VerifyPassword", vl_method_verify_password,
					  "org.openSUSE.pwaccess.ExpiredCheck",   vl_method_expired_check,
					  "org.openSUSE.pwaccess.GetEnvironment", vl_method_get_environment,
					  "org.openSUSE.pwaccess.Ping",           vl_method_ping,
					  "org.openSUSE.pwaccess.Quit",           vl_method_quit,
					  "org.openSUSE.pwaccess.SetLogLevel",    vl_method_set_log_level);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind Varlink methods: %s",
	      strerror(-r));
      return r;
    }

  sd_varlink_server_set_userdata (varlink_server, event);

  r = sd_varlink_server_attach_event (varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to attach to event: %s", strerror (-r));
      return r;
    }

  r = sd_varlink_server_listen_auto (varlink_server);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to listen: %s", strerror (-r));
      return r;
    }


  if (!socket_activation)
    {
      r = sd_varlink_server_listen_address(varlink_server, _VARLINK_PWACCESS_SOCKET, 0666);
      if (r < 0)
	{
	  log_msg (LOG_ERR, "Failed to bind to Varlink socket: %s", strerror (-r));
	  return r;
	}
    }

  announce_ready();
  if (socket_activation)
    r = varlink_event_loop_with_idle(event, varlink_server);
  else
    r = sd_event_loop(event);
  announce_stopping();

  return r;
}

static void
print_help (void)
{
  printf("pwaccessd - manage passwd and shadow\n");

  printf("  -s, --socket   Activation through socket\n");
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
	case 's':
	  socket_activation = true;
	  break;
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
          fprintf (stdout, "pwaccessd (%s) %s\n", PACKAGE, VERSION);
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
      fprintf (stderr, "Try `pwaccessd --help' for more information.\n");
      return 1;
    }

  log_msg (LOG_INFO, "Starting pwaccessd (%s) %s...", PACKAGE, VERSION);

  int r = run_varlink ();
  if (r < 0)
    {
      log_msg (LOG_ERR, "ERROR: varlink loop failed: %s", strerror (-r));
      return -r;
    }

  log_msg (LOG_INFO, "pwaccessd stopped.");

  return 0;
}
