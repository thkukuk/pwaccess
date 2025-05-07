//SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <string.h>
#include <systemd/sd-varlink.h>

#include "basics.h"
#include "pwaccess.h"

static int
connect_to_pwaccessd(sd_varlink **ret, const char *socket, char **error)
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

  *ret = TAKE_PTR(link);
  return 0;
}

struct user_record {
  bool success;
  char *error;
  bool complete;
  struct passwd *pw;
  struct spwd *sp;
  sd_json_variant *content_passwd;
  sd_json_variant *content_shadow;
};

struct passwd *
struct_passwd_free(struct passwd *var)
{
  var->pw_name = mfree(var->pw_name);
  if (var->pw_passwd)
    {
      explicit_bzero(var->pw_passwd, strlen(var->pw_passwd));
      var->pw_passwd = mfree(var->pw_passwd);
    }
  var->pw_gecos = mfree(var->pw_gecos);
  var->pw_dir = mfree(var->pw_dir);
  var->pw_shell = mfree(var->pw_shell);

  return NULL;
}

void
struct_passwd_freep(struct passwd **var)
{
  if (!var || !*var)
    return;

  struct_passwd_free(*var);
  *var = mfree(*var);
}

struct spwd *
struct_shadow_free(struct spwd *var)
{
  var->sp_namp = mfree(var->sp_namp);
  if (var->sp_pwdp)
    {
      explicit_bzero(var->sp_pwdp, strlen(var->sp_pwdp));
      var->sp_pwdp = mfree(var->sp_pwdp);
    }

  return NULL;
}

void
struct_shadow_freep(struct spwd **var)
{
  if (!var || !*var)
    return;

  struct_shadow_free(*var);
  *var = mfree(*var);
}

static void
user_record_free(struct user_record *var)
{
  var->error = mfree(var->error);
  var->content_passwd = sd_json_variant_unref(var->content_passwd);
  var->content_shadow = sd_json_variant_unref(var->content_shadow);
}

int
pwaccess_get_user_record(int64_t uid, const char *user, struct passwd **ret_pw, struct spwd **ret_sp,
			 bool *complete, char **error)
{
  _cleanup_(user_record_free) struct user_record p = {
    .success = false,
    .error = NULL,
    .content_passwd = NULL,
    .content_shadow = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct user_record, success), 0 },
    { "ErrorMsg",   SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct user_record, error), 0 },
    { "Complete",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct user_record, complete), 0 },
    { "passwd",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct user_record, content_passwd), 0 },
    { "shadow",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct user_record, content_shadow), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result;
  const char *error_id = NULL;
  int r;

  r = connect_to_pwaccessd(&link, _VARLINK_PWACCESS_SOCKET, error);
  if (r < 0)
    return r;

  if (uid >= 0)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_INTEGER("uid", uid));
  if (r >= 0 && user)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR_STRING("userName", user));
  if (r < 0)
    {
      fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
    }
  r = sd_varlink_call(link, "org.openSUSE.pwaccess.GetUserRecord", params, &result, &error_id);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call GetUserRecord method: %s\n", strerror(-r));
      return r;
    }
  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      fprintf(stderr, "Failed to parse JSON answer: %s\n", strerror(-r));
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = p.error;
	  else
	    *error = strdup(error_id); /* XXX NULL ckeck */
	}
      return -EIO;
    }

  if (p.content_passwd == NULL)
    {
      printf("No entry found\n");
      return 0;
    }

  _cleanup_(struct_passwd_freep) struct passwd *pw = calloc(1, sizeof(struct passwd)); /* XXX check NULL */
  static const sd_json_dispatch_field dispatch_passwd_table[] = {
    { "name",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_name),   SD_JSON_MANDATORY },
    { "passwd", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_passwd), 0 },
    { "UID",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,   offsetof(struct passwd, pw_uid),    SD_JSON_MANDATORY },
    { "GID",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,   offsetof(struct passwd, pw_gid),    SD_JSON_MANDATORY },
    { "GECOS",  SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_gecos),  0 },
    { "dir",    SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_dir),    0 },
    { "shell",  SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct passwd, pw_shell),  0 },
    {}
  };

  r = sd_json_dispatch(p.content_passwd, dispatch_passwd_table, SD_JSON_ALLOW_EXTENSIONS, pw);
  if (r < 0)
    {
      fprintf(stderr, "Failed to parse JSON passwd entry: %s\n", strerror(-r));
      return r;
    }

  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  if (p.content_shadow)
    {
      sp = calloc(1, sizeof(struct spwd)); /* XXX check NULL */
      static const sd_json_dispatch_field dispatch_shadow_table[] = {
	{ "name",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct spwd, sp_namp),   SD_JSON_MANDATORY },
	{ "passwd", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct spwd, sp_pwdp),   0 },
	{ "lstchg", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_lstchg), 0 },
	{ "min",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_min),    0 },
	{ "max",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_max),    0 },
	{ "warn",   SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_warn),   0 },
	{ "inact",  SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_inact),  0 },
	{ "expire", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_expire), 0 },
	{ "flag",   SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct spwd, sp_flag),   0 },
	{}
      };

      r = sd_json_dispatch(p.content_shadow, dispatch_shadow_table, SD_JSON_ALLOW_EXTENSIONS, sp);
      if (r < 0)
	{
	  fprintf(stderr, "Failed to parse JSON shadow entry: %s\n", strerror(-r));
	  return r;
	}
    }

  if (complete)
    *complete = p.complete;

  if (ret_pw)
    *ret_pw = TAKE_PTR(pw);

  if (ret_sp)
    *ret_sp = TAKE_PTR(sp);

  return 0;
}
