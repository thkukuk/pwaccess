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

struct user_record {
  bool success;
  char *error;
  bool complete;
  bool pwchangeable;
  int expired;
  long daysleft;
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
    { "passwd",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct user_record, content_passwd), SD_JSON_NULLABLE },
    { "shadow",     SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant, offsetof(struct user_record, content_shadow), SD_JSON_NULLABLE },
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
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  sd_json_variant *result = NULL;
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
      return r;
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
      int retval = -EIO;

      if (error)
	{
	  if (p.error)
	    *error = TAKE_PTR(p.error);
	  else
	    {
	      *error = strdup(error_id);
	      if (*error == NULL)
		retval = -ENOMEM;
	    }
	}

      /* Yes, we will overwrite a possible ENOMEM, but
	 this shouldn't matter here */
      if (streq(error_id, "org.openSUSE.pwaccess.NoEntryFound"))
	retval = -ENODATA;

      return retval;
    }

  if (!p.success) /* we should never have this case, but be safe */
    {
      if (error)
	*error = TAKE_PTR(p.error);
      return -EIO;
    }

  if (sd_json_variant_is_null(p.content_passwd))
    {
      printf("No entry found\n");
      return 0;
    }

  pw = calloc(1, sizeof(struct passwd));
  if (pw == NULL)
    return -ENOMEM;

  r = sd_json_dispatch(p.content_passwd, dispatch_passwd_table, SD_JSON_ALLOW_EXTENSIONS, pw);
  if (r < 0)
    {
      fprintf(stderr, "Failed to parse JSON passwd entry: %s\n", strerror(-r));
      return r;
    }

  if (!sd_json_variant_is_null(p.content_shadow) && sd_json_variant_elements(p.content_shadow) > 0)
    {
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

      sp = calloc(1, sizeof(struct spwd));
      if (sp == NULL)
	return -ENOMEM;

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

int
pwaccess_verify_password(const char *user, const char *password, bool nullok, bool *ret_authenticated, char **error)
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
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result = NULL;
  const char *error_id = NULL;
  int r;

  /* make sure caller does not ignore error code but uses this instead */
  if (ret_authenticated)
    *ret_authenticated = false;

  if (!user || !ret_authenticated)
    return -EINVAL;

  r = connect_to_pwaccessd(&link, _VARLINK_PWACCESS_SOCKET, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user)),
		     SD_JSON_BUILD_PAIR("password", SD_JSON_BUILD_STRING(strempty(password))),
		     SD_JSON_BUILD_PAIR("nullOK", SD_JSON_BUILD_BOOLEAN(nullok)));
  if (r < 0)
    {
      fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
      return r;
    }

  sd_json_variant_sensitive(params); /* password is sensitive */

  r = sd_varlink_call(link, "org.openSUSE.pwaccess.VerifyPassword", params, &result, &error_id);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call VerifyPassword method: %s\n", strerror(-r));
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
      int retval = -EIO;

      if (error)
	{
	  if (p.error)
	    *error = TAKE_PTR(p.error);
	  else
	    {
	      *error = strdup(error_id);
	      if (*error == NULL)
		retval = -ENOMEM;
	    }
	}

      /* Yes, we will overwrite a possible ENOMEM, but
	 this shouldn't matter here */
      if (streq(error_id, "org.openSUSE.pwaccess.NoEntryFound"))
	retval = -ENODATA;

      return retval;
    }

  if (!p.success) /* no success and no error means password does not match */
    {
      if (error)
	*error = TAKE_PTR(p.error);
      return 0;
    }

  *ret_authenticated = true;

  return 0;
}


/* return values:
   < 0: error occured
     0: all fine
   > 0: PWA_EXPIRED_*
*/
int
pwaccess_check_expired(const char *user, long *daysleft, bool *pwchangeable, char **error)
{
  _cleanup_(user_record_free) struct user_record p = {
    .success = false,
    .error = NULL,
    .content_passwd = NULL,
    .content_shadow = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct user_record, success), 0 },
    { "ErrorMsg",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct user_record, error), 0 },
    { "Expired",      SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,     offsetof(struct user_record, expired), 0 },
    { "DaysLeft",     SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64,   offsetof(struct user_record, daysleft), 0 },
    { "PWChangeAble", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct user_record, pwchangeable), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result = NULL;
  const char *error_id = NULL;
  int r;

  if (!user)
    return -EINVAL;

  r = connect_to_pwaccessd(&link, _VARLINK_PWACCESS_SOCKET, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(user)));
  if (r < 0)
    {
      fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
      return r;
    }

  r = sd_varlink_call(link, "org.openSUSE.pwaccess.ExpiredCheck", params, &result, &error_id);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call CheckExpired method: %s\n", strerror(-r));
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
      int retval = -EIO;

      if (error)
	{
	  if (p.error)
	    *error = TAKE_PTR(p.error);
	  else
	    {
	      *error = strdup(error_id);
	      if (*error == NULL)
		retval = -ENOMEM;
	    }
	}

      /* Yes, we will overwrite a possible ENOMEM, but
	 this shouldn't matter here */
      if (streq(error_id, "org.openSUSE.pwaccess.NoEntryFound"))
	retval = -ENODATA;

      return retval;
    }

  if (!p.success)
    {
      if (error)
	*error = TAKE_PTR(p.error);
      return 0;
    }

  if (daysleft)
    *daysleft = p.daysleft;

  if (pwchangeable)
    *pwchangeable = p.pwchangeable;

  return p.expired;
}
