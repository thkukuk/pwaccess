//SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <assert.h>
#include <crypt.h>

#include "basics.h"
#include "verify.h"

bool
is_shadow(const struct passwd *pw)
{
  assert(pw);

  if (streq(pw->pw_passwd, "x") ||
      ((pw->pw_passwd[0] == '#') &&
       (pw->pw_passwd[1] == '#') &&
       (strcmp(pw->pw_name, pw->pw_passwd + 2) == 0)))
    return true;

  return false;
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

  if (p && p[0] == '\0' && !nullok)
    return VERIFY_FAILED;
  else if (strlen(hash) == 0)
    {
      if (p && p[0] == '\0' && nullok)
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
