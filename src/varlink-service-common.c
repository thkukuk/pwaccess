// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <syslog.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-journal.h>

#include "basics.h"
#include "varlink-service-common.h"

static int log_level = LOG_WARNING;

void
set_max_log_level(int level)
{
  log_level = level;
}

void
log_msg(int priority, const char *fmt, ...)
{
  static int is_tty = -1;

  if (priority > log_level)
    return;

  if (is_tty == -1)
    is_tty = isatty(STDOUT_FILENO);

  va_list ap;

  va_start(ap, fmt);

  if (is_tty)
    {
      if (priority <= LOG_ERR)
        {
          vfprintf(stderr, fmt, ap);
          fputc('\n', stderr);
        }
      else
        {
          vprintf(fmt, ap);
          putchar('\n');
        }
    }
  else
    sd_journal_printv(priority, fmt, ap);

  va_end(ap);
}

int
vl_method_ping(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  int r;

  log_msg(LOG_INFO, "Varlink method \"Ping\" called...");

  r = sd_varlink_dispatch(link, parameters, NULL, NULL);
  if (r != 0)
    return r;

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Alive", true));
}

int
vl_method_set_log_level(sd_varlink *link, sd_json_variant *parameters,
			sd_varlink_method_flags_t _unused_(flags),
			void _unused_(*userdata))
{
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Level", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, 0, SD_JSON_MANDATORY },
    {}
  };

  int r, level;

  log_msg(LOG_INFO, "Varlink method \"SetLogLevel\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
  if (r != 0)
    return r;

  log_msg(LOG_DEBUG, "Log level %i requested", level);

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "SetLogLevel: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  set_max_log_level(level);

  log_msg(LOG_INFO, "New log setting: level=%i", level);

  return sd_varlink_reply(link, NULL);
}

int
vl_method_get_environment(sd_varlink *link, sd_json_variant *parameters,
			  sd_varlink_method_flags_t _unused_(flags),
			  void _unused_(*userdata))
{
  int r;

  log_msg(LOG_INFO, "Varlink method \"GetEnvironment\" called...");

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "GetEnvironment: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  sleep(10);

  r = sd_varlink_dispatch(link, parameters, NULL, NULL);
  if (r != 0)
    return r;

#if 0 /* XXX */
  for (char **e = environ; *e != 0; e++)
    {
      if (!env_assignment_is_valid(*e))
	goto invalid;
      if (!utf8_is_valid(*e))
	goto invalid;
    }
#endif

  sleep(10);

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRV("Environment", environ));

#if 0
 invalid:
  return sd_varlink_error(link, "io.systemd.service.InconsistentEnvironment", parameters);
#endif
}

int
vl_method_quit(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void *userdata)
{
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ExitCode", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, 0, 0 },
    {}
  };
  uid_t peer_uid;
  sd_event *loop = userdata;
  int exit_code = 0;
  int r;

  log_msg(LOG_INFO, "Varlink method \"Quit\" called...");

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "Quit: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &exit_code);
  if (r != 0)
    {
      log_msg (LOG_ERR, "Quit request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  /* exit code must be negative, systemd will convert that to a positive
     value */
  if (exit_code > 0)
    exit_code = -exit_code;

  r = sd_event_exit(loop, exit_code);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Quit request: disabling event loop failed: %s",
	      strerror(-r));
      return sd_varlink_errorbo(link, "org.openSUSE.pwaccess.InternalError",
                                SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}
