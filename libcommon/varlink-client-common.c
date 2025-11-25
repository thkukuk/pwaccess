// SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <systemd/sd-varlink.h>
#include <security/pam_misc.h>

#include "basics.h"
#include "varlink-client-common.h"

struct result *
struct_result_free(struct result *var)
{
  var->error = mfree((char *)var->error);
  return NULL;
}

int
connect_to_pwupdd(sd_varlink **ret, const char *socket, char **error)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  int r;

  r = sd_varlink_connect_address(&link, socket);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to connect to %s: %s",
                      socket, strerror(-r)) < 0)
          {
            error = NULL;
            r = -ENOMEM;
          }
      return r;
    }

  /* Mark anything we get from the service as sensitive */
  r = sd_varlink_set_input_sensitive(link);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to enable sensitive Varlink input: %s",
                      strerror(-r)) < 0)
          {
            error = NULL;
            r = -ENOMEM;
          }
      return r;
    }

  *ret = TAKE_PTR(link);
  return 0;
}

static struct pam_message *
pam_message_free(struct pam_message *var)
{
  var->msg = mfree((char *)var->msg);
  return NULL;
}

struct pam_response *resp = NULL;

int
reply_callback(sd_varlink *link _unused_,
	       sd_json_variant *parameters,
	       const char *error,
	       sd_varlink_reply_flags_t flags _unused_,
	       void *userdata _unused_)
{
  _cleanup_(pam_message_free) struct pam_message pmsg = {
    .msg_style = -1,
    .msg = NULL
  };
  static const sd_json_dispatch_field dispatch_pmsg_table[] = {
    { "msg_style", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,    offsetof(struct pam_message, msg_style), SD_JSON_MANDATORY },
    { "message",   SD_JSON_VARIANT_STRING,  sd_json_dispatch_string, offsetof(struct pam_message, msg),       SD_JSON_NULLABLE },
    {}
  };
  _cleanup_(struct_result_free) struct result p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_result_table[] = {
    { "Success",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct result, success), SD_JSON_MANDATORY },
    { "ErrorMsg",   SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct result, error), 0 },
    {}
  };
  int r;

  if (error)
    {
      r = sd_json_dispatch(parameters, dispatch_result_table, SD_JSON_ALLOW_EXTENSIONS, &p);
      if (r < 0)
	{
	  /* Mandatory field not found, so no pam_message but final end message */
	  fprintf(stderr, "Failed to parse JSON answer (result) for error '%s': %s\n", error, strerror(-r));
	  return r;
	}
      if (p.success || !p.error) /* Oops, something did go wrong */
	fprintf(stderr, "Method call failed: %s\n", error);
      else
	fprintf(stderr, "%s\n", p.error);

      /* If we can translate this to an errno, let's print that as errno
	 and return it, otherwise, return a generic error code. */
      r = sd_varlink_error_to_errno(error, parameters);
      return r;
    }

  //sd_json_variant_dump(parameters, SD_JSON_FORMAT_NEWLINE, stdout, NULL);

  r = sd_json_dispatch(parameters, dispatch_pmsg_table, SD_JSON_ALLOW_EXTENSIONS, &pmsg);
  if (r < 0)
    {
      /* Mandatory field not found, so no pam_message but final end message */
      if (r != -ENXIO)
	{
	  fprintf(stderr, "Failed to parse JSON answer (pam_message): %s\n", strerror(-r));
	  return r;
	}
        r = sd_json_dispatch(parameters, dispatch_result_table, SD_JSON_ALLOW_EXTENSIONS, &p);
	if (r < 0)
	  {
	    /* Mandatory field not found, so no pam_message but final end message */
	    fprintf(stderr, "Failed to parse JSON answer (result): %s\n", strerror(-r));
	    return r;
	  }
	if (!p.success)
	  {
	    if (p.error)
	      fprintf(stderr, "%s\n", p.error);
	    else
	      fprintf(stderr, "Error while changing account data.\n");
	    return 1;
	  }
    }
  else /* got pam_message */
    {
      const struct pam_message *arg = &pmsg;
      r = misc_conv(1, &arg, &resp, NULL);
      if (r != PAM_SUCCESS)
	{
	  fprintf(stderr, "misc_conv() failed: %s\n", pam_strerror(NULL, r));
	  return -EBADMSG;
	}

      if (resp && pmsg.msg_style != PAM_PROMPT_ECHO_OFF && pmsg.msg_style != PAM_PROMPT_ECHO_ON)
	{
	  if (resp->resp)
	    free(resp->resp);
	  resp = mfree(resp);
	}
    }

  return r;
}
