// SPDX-License-Identifier: GPL-2.0-or-later

#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <libeconf.h>

#include "basics.h"
#include "read_config.h"

/* trim leading and trailing whitespaces */
static char *
trim_whitespace(char *str)
{
  char *end;

  while(isspace((unsigned char)*str))
    str++;

  if(*str == '\0')
    return str;

  end = str + strlen(str) - 1;

  while(end > str && isspace((unsigned char)*end))
    end--;

  *(end+1) = 0;
  return str;
}

/* function to resolve a single user string (name or UID) to a uid_t
   Returns 0 on success, -errno on failure */
static int
parse_token(const char *token, uid_t *result_uid)
{
  if (isempty(token))
    return -EINVAL;

  /* if the first character is a number, it must be a UID */
  if (isdigit(token[0]))
    {
      char *ep;
      long long ll;

      errno = 0;
      ll = strtol(token, &ep, 10);
      if (errno == ERANGE || ll < 0 || ll > UINT32_MAX ||
	  token == ep || *ep != '\0')
	{
	  if (errno == 0)
	    return -EINVAL;
	  else
	    return -errno;
	}
      *result_uid = (uid_t)ll;
      return 0;
    }
  else /* Try as username */
    {
      struct passwd *pwd;

      errno = 0;
      pwd = getpwnam(token);
      if (pwd == NULL)
	{
	  if (errno == 0)
	    return -ENODATA;
	  else
	    return -errno;
	}

      *result_uid = pwd->pw_uid;
    }
  return 0;
}

static econf_err
lookup_group(econf_file *key_file, const char *group, uid_t **list)
{
  _cleanup_free_ char *value = NULL;
  _cleanup_free_ uid_t *uids = NULL;
  econf_err error;

  *list = NULL;

  /* look at first in method specific group */
  error = econf_getStringValue(key_file, group, "allow", &value);
  if (error == ECONF_NOKEY || error == ECONF_NOGROUP)
    /* Fallback if key not found */
    error = econf_getStringValue(key_file, "global", "allow", &value);
  if (error == ECONF_NOKEY || error == ECONF_NOGROUP)
    /* no data, done */
    return ECONF_SUCCESS;
  /* error out in other cases */
  if (error != ECONF_SUCCESS)
    return error;

  if (isempty(value))
    return ECONF_SUCCESS;

  /* split value into tokens and parse them */

  /* count number of tokens */
  size_t count = 0;
  for (size_t i = 0; value[i] != '\0'; i++)
    if (value[i] == ',')
      count++;
  count++;

  /* allocate one more slot for the final "NULL" */
  uids = calloc(count + 1, sizeof (uid_t));

  /* Split and store */
  count = 0;
  char *token = strtok(value, ",");
  while (token != NULL)
    {
      uid_t uid = 0;
      int r;

      token = trim_whitespace(token);
      r = parse_token(token, &uid);
      token = strtok(NULL, ",");
      if (r < 0)
	{
	  /* XXX we need a good warning */
	  continue; /* continue with the other user */
	}
      if (uid == 0) /* root is allways allowed, ignore */
	continue;
      uids[count++] = uid;
    }
  uids[count] = 0;

  *list = TAKE_PTR(uids);

  return ECONF_SUCCESS;
}

/* we will read everything and only report the firstx error */
econf_err
read_config(struct config_t *cfg)
{
  _cleanup_(econf_freeFilep) econf_file *key_file = NULL;
  econf_err error;
  econf_err retval = ECONF_SUCCESS;

#ifdef TESTSDIR
  error = econf_newKeyFile_with_options(&key_file, "ROOT_PREFIX="TESTSDIR);
  if (error)
    return error;
#endif

  /* This looks for pwaccessd.conf{.d} in /usr/share/account-utils/
     or /etc/account-utils/ */
  error = econf_readConfig(&key_file,
			   "account-utils", /* project name */
			   "/usr/share",    /* directory below /usr */
			   "pwaccessd",     /* file name without extension */
			   "conf",          /* suffix */
			   "=",             /* delimiter */
			   "#");            /* comment */
  if (error != ECONF_SUCCESS)
    return error;

  /* XXX read debug_level from [global] and set max_log_level */

  error = lookup_group(key_file, "GetUserRecord", &(cfg->allow_get_user_record));
  if (error && !retval)
    retval = error;
  error = lookup_group(key_file, "VerifyPassword", &(cfg->allow_verify_password));
  if (error && !retval)
    retval = error;
  error = lookup_group(key_file, "ExpiredCheck", &(cfg->allow_expired_check));
  if (error && !retval)
    return error;

  return retval;
}
