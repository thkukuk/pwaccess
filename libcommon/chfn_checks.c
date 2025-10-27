//SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <stdlib.h>
#include <wctype.h>
#include <wchar.h>

#include "basics.h"
#include "chfn_checks.h"

bool
may_change_field(uid_t uid, char field)
{
  const char *cp;

  /* root is always allowed to change everything.  */
  if (uid == 0)
    return true;

  /* CHFN_RESTRICT specifies exactly which fields may be changed
     by regular users.  */
  // XXX cp = getlogindefs_str("CHFN_RESTRICT", "");
  cp = "rwh";

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
    return false; /* XXX set *error */

  r = mbstowcs_alloc(illegal, &willegal);
  if (r < 0)
    return false; /* XXX set *error */

  for (size_t i = 0; i < wcslen(wstr); i++)
    {
      wchar_t c = wstr[i];
      if (wcschr(willegal, c) != NULL || c == '"' || c == '\n')
        {
          // XX printf (_("%s: The characters '%s\"' are not allowed.\n"),
	  // program, illegal);
          return false;
        }
      if (iswcntrl (c))
        {
          // XXX printf (_("%s: Control characters are not allowed.\n"), program);
          return false;
        }
    }

  return true;
}
