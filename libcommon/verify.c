// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <assert.h>
#include <crypt.h>
#include <limits.h>
#include <time.h>

#include "pwaccess.h"
#include "basics.h"
#include "verify.h"

bool
valid_name(const char *name)
{
  /* This function tests if the name has invalid characters, not if the
     name is really valid.

     User/group names must match BRE regex:
     [a-zA-Z0-9_.][a-zA-Z0-9_.-]*$\?

     Reject every name containing additional characters.
  */

  if (isempty(name))
    return false;

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
        return false;
      ++name;
    }

  return true; 
}

bool
is_shadow(const struct passwd *pw)
{
  assert(pw);

  if (isempty(pw->pw_passwd))
    return false;

  if (streq(pw->pw_passwd, "x") ||
      (pw->pw_passwd &&
       strlen(pw->pw_passwd) > 2 &&
       (pw->pw_passwd[0] == '#') &&
       (pw->pw_passwd[1] == '#') &&
       streq(pw->pw_name, pw->pw_passwd + 2)))
    return true;

  return false;
}

int
expired_check(const struct spwd *sp, long *daysleft, bool *pwchangeable)
{
  long int now, passed;

  assert(sp);

  if (daysleft)
    *daysleft = -1;

  if (pwchangeable)
    *pwchangeable = true;

  now = time(NULL) / (60 * 60 * 24);

  /* account expired */
  /* XXX ">= 0" or "> 0"? shadow and pam disagree here */
  if (sp->sp_expire >= 0 && now >= sp->sp_expire)
    return PWA_EXPIRED_YES;

  /* new password required */
  if (sp->sp_lstchg == 0)
    {
      if (daysleft)
	*daysleft = 0;
      return PWA_EXPIRED_CHANGE_PW;
    }

  /* password aging disabled */
  /* The last and max fields must be present for an account
     to have an expired password. A maximum of >10000 days
     is considered to be infinite. */
  if (sp->sp_lstchg == -1 ||
      sp->sp_max == -1 ||
      sp->sp_max >= 10000)
    return PWA_EXPIRED_NO;

  passed = now - sp->sp_lstchg;
  if (sp->sp_max >= 0)
    {
      if (sp->sp_inact >= 0)
	{
	  long inact = sp->sp_max < LONG_MAX - sp->sp_inact ? sp->sp_max + sp->sp_inact : LONG_MAX;
	  if (passed >= inact)
	    {
	      /* authtok expired */
	      if (daysleft)
		*daysleft = inact - passed;
	      return PWA_EXPIRED_DISABLED;
	    }
	}
      /* needs a new password */
      if (passed >= sp->sp_max)
	return PWA_EXPIRED_CHANGE_PW;

      if (sp->sp_warn > 0)
	{
	  long warn = sp->sp_warn > sp->sp_max ? -1 : sp->sp_max - sp->sp_warn;
	  if (passed >= warn && daysleft) /* warn before expire */
	    *daysleft = sp->sp_max - passed;
	}
    }

  if (sp->sp_min > 0 && passed < sp->sp_min && pwchangeable)
    /* The last password change was too recent. */
    *pwchangeable = false;

  return PWA_EXPIRED_NO;
}

static inline int
consttime_streq(const char *userinput, const char *secret)
{
  volatile const char *u = userinput, *s = secret;
  volatile int ret = 0;

  do {
    ret |= *u ^ *s;

    s += !!*s;
  } while (*u++ != '\0');

  return ret == 0;
}

int
verify_password(const char *hash, const char *p, bool nullok)
{
  _cleanup_free_ char *pp = NULL;

  if (isempty(p) && !nullok)
    return VERIFY_FAILED;
  else if (strlen(hash) == 0)
    {
      if (isempty(p) && nullok)
	return VERIFY_OK;
      else
	return VERIFY_FAILED;
    }
  else if (!p || *hash == '*' || *hash == '!')
    return VERIFY_FAILED;
  else
    {
      /* Get the status of the hash from checksalt */
      int retval_checksalt = crypt_checksalt(hash);

      /*
       * Check for hashing methods that are disabled by
       * libcrypt configuration and/or system preset.
       */
      if (retval_checksalt == CRYPT_SALT_METHOD_DISABLED)
	return VERIFY_CRYPT_DISABLED;
      if (retval_checksalt == CRYPT_SALT_INVALID)
	return VERIFY_CRYPT_INVALID;

      struct crypt_data *cdata;
      cdata = calloc(1, sizeof(*cdata));
      if (cdata != NULL)
	{
	  pp = strdup(crypt_r(p, hash, cdata));
	  explicit_bzero(cdata, sizeof(struct crypt_data));
	  free(cdata);
	}
    }

  if (pp && consttime_streq(pp, hash))
    return VERIFY_OK;

  return VERIFY_FAILED;
}
