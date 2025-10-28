// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <stdio.h>
#include <systemd/sd-varlink.h>

#include "chauthtok.h"
#include "basics.h"
#include "varlink-client-common.h"

#define USEC_INFINITY ((uint64_t) UINT64_MAX)

int
chauthtok(const char *user, int pam_flags)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_free_ char *error = NULL;
  int r;

  r = connect_to_pwupdd(&link, _VARLINK_PWUPD_SOCKET, &error);
  if (r < 0)
    {
      if (error)
	fprintf(stderr, "%s\n", error);
      else
	fprintf(stderr, "Cannot connect to pwupd! (%s)\n", strerror(-r));
      return -r;
    }

  r = sd_json_variant_merge_objectbo(&params,
				     SD_JSON_BUILD_PAIR_STRING("userName", user));
  if (r < 0)
    {
      fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
      return -r;
    }

  if (pam_flags)
    {
      r = sd_json_variant_merge_objectbo(&params,
					 SD_JSON_BUILD_PAIR_INTEGER("flags", pam_flags));
      if (r < 0)
	{
	  fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
	  return -r;
	}
    }

  r = sd_varlink_bind_reply(link, reply_callback);
  if (r < 0)
    {
      fprintf(stderr, "Failed to bind reply callback: %s\n", strerror(-r));
      return -r;
    }

  r = sd_varlink_observe(link, "org.openSUSE.pwupd.Chauthtok", params);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call chauthtok method: %s\n", strerror(-r));
      return -r;
    }

 loop:
  for (;;)
    {
      r = sd_varlink_is_idle(link);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to check if varlink connection is idle: %s\n", strerror(-r));
	  return -r;
	}
      if (r > 0)
	break;

      r = sd_varlink_process(link);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to process varlink connection: %s\n", strerror(-r));
	  return -r;
	}
      if (r != 0)
	continue;

      r = sd_varlink_wait(link, USEC_INFINITY);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to wait for varlink connection events: %s\n", strerror(-r));
	  return -r;
	}
    }

  if (resp)
    {
      _cleanup_(sd_json_variant_unrefp) sd_json_variant *answer = NULL;

      r = sd_json_buildo(&answer,
			 SD_JSON_BUILD_PAIR("response", SD_JSON_BUILD_STRING(resp->resp)));
      if (r < 0)
	{
	  fprintf(stderr, "Failed to build response list: %s\n", strerror(-r));
	  return -r;
	}

      free(resp->resp);
      resp = mfree(resp);

      sd_json_variant_sensitive(answer); /* password is sensitive */

      r = sd_varlink_observe(link, "org.openSUSE.pwupd.Conv", answer);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to call conv method: %s\n", strerror(-r));
	  return -r;
	}
      goto loop;
    }

  return 0;
}
