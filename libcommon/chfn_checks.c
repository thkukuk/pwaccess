//SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <wctype.h>
#include <wchar.h>
#include <libeconf.h>

#include "basics.h"
#include "chfn_checks.h"

static const char *
get_chfn_restrict(char **ret_error)
{
  static const char *value = NULL;
  _cleanup_(econf_freeFilep) econf_file *key_file = NULL;
  econf_err error;
  char *val = NULL;

  if (value)
    return value;

  error = econf_readConfig(&key_file,
                           NULL /* project */,
                           _PATH_VENDORDIR /* usr_conf_dir */,
                           "login" /* config_name */,
                           "defs" /* config_suffix */,
                           "= \t" /* delim */,
                           "#" /* comment */);
  if (error != ECONF_SUCCESS)
    {
      if (ret_error)
	{
	  _cleanup_free_ char *errstr = NULL;

	  if (asprintf(&errstr, "Cannot parse login.defs: %s",
		       econf_errString(error)) < 0)
	    *ret_error = NULL;
	  else
	    *ret_error = TAKE_PTR(errstr);
	}
      return ""; /* be very restrictive, allow nothing */
    }

  error = econf_getStringValue (key_file, NULL, "CHFN_RESTRICT", &val);
  if (error != ECONF_SUCCESS)
    {
      if (ret_error)
	{
	  _cleanup_free_ char *errstr = NULL;

	  if (asprintf(&errstr, "Error reading CHFN_RESTRICT: %s",
		       econf_errString(error)) < 0)
	    *ret_error = NULL;
	  else
	    *ret_error = TAKE_PTR(errstr);
	}
      return "";
    }
  else value = val;

  return value;
}

bool
may_change_field(uid_t uid, char field, char **error)
{
  const char *cp;

  /* root is always allowed to change everything.  */
  if (uid == 0)
    return true;

  /* CHFN_RESTRICT specifies exactly which fields may be changed
     by regular users.  */
  cp = get_chfn_restrict(error);
  if (error && *error)
    return false;

  if (strchr(cp, field))
    return true;

  return false;
}

/* convert a multibye string to a wide character string, so
   that we can use iswprint.  */
static int
mbstowcs_alloc (const char *string, wchar_t **ret)
{
  size_t size;
  _cleanup_free_ wchar_t *buf = NULL;

  if (!string)
    return -EINVAL;

  /*
   * it seems this spot here can break if `mbstowcs` is not happy with the
   * encoding or something.
   *
   * I provided this input to org.openSUSE.pwupd.Chfn
   *
   * {
   *         "userName": "mgerstner",
   *         "homePhone": "stuff;böp"
   * }
   *
   * this resulted in:
   *
   *    Nov 20 10:29:35 localhost.localdomain systemd-coredump[2453]:
   *        Process 2451 (pwupdd) of user 0 dumped core.
   *    Stack trace of thread 2451:
   *    #0  0x00007f24ef89dd3c __pthread_kill_implementation (libc.so.6 + 0x9dd3c)
   *    #1  0x00007f24ef8427b6 __GI_raise (libc.so.6 + 0x427b6)
   *    #2  0x00007f24ef82934b __GI_abort (libc.so.6 + 0x2934b)
   *    #3  0x00007f24ef82a3ad __libc_message_impl (libc.so.6 + 0x2a3ad)
   *    #4  0x00007f24ef92d42b __GI___fortify_fail (libc.so.6 + 0x12d42b)
   *    #5  0x00007f24ef92ccf6 __GI___chk_fail (libc.so.6 + 0x12ccf6)
   *    #6  0x00007f24ef92dd35 __mbstowcs_chk (libc.so.6 + 0x12dd35)
   *    #7  0x000055c54341df05 mbstowcs_alloc.constprop.0 (/usr/libexec/pwupdd + 0x6f05)
   *    #8  0x000055c54341df87 chfn_check_string (/usr/libexec/pwupdd + 0x6f87)
   *    #9  0x000055c54341e43e vl_method_chfn (/usr/libexec/pwupdd + 0x743e)
   *    #10 0x00007f24efbc8ff6 sd_varlink_process (libsystemd.so.0 + 0xa5ff6)
   */
  size = mbstowcs(NULL, string, 0);
  buf = calloc(size + 1, sizeof(wchar_t));
  if (buf == NULL)
    return -ENOMEM;

  size = mbstowcs (buf, string, size);
  if (size == (size_t) -1)
    return -EINVAL;

  *ret = TAKE_PTR(buf);
  return 0;
}

bool
chfn_check_string(const char *string, const char *illegal, char **error)
{
  _cleanup_free_ wchar_t *wstr = NULL;
  _cleanup_free_ wchar_t *willegal = NULL;
  int r;

  if (error)
    *error = NULL;

  r = mbstowcs_alloc(string, &wstr);
  if (r < 0)
    {
      if (error)
	*error = strdup(strerror(-r));
      return false;
    }

  r = mbstowcs_alloc(illegal, &willegal);
  if (r < 0)
    {
      if (error)
	*error = strdup(strerror(-r));
      return false;
    }

  for (size_t i = 0; i < wcslen(wstr); i++)
    {
      wchar_t c = wstr[i];
      if (wcschr(willegal, c) != NULL || c == '\n')
        {
	  if (error)
	    if (asprintf(error, "The characters '%s\\n' are not allowed.",
			 illegal) < 0)
	      *error = NULL;
          return false;
        }
      if (iswcntrl (c))
        {
	  if (error)
	  *error = strdup("Control characters are not allowed.");
          return false;
        }
    }

  return true;
}
