// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>

#include "basics.h"
#include "files.h"

#include "files.c"
#include "string-util-fundamental.c"

int
main(int argc _unused_, char **argv _unused_)
{
  struct passwd pwd;
  int r;

  r = update_passwd(NULL, NULL);
  if (r != -EINVAL)
    {
      fprintf(stderr, "update_passwd(NULL, NULL) did return %i\n", r);
      return 1;
    }

  memset(&pwd, 0, sizeof(pwd));
  pwd.pw_name = "test0";

  r = update_passwd(&pwd, TESTSDIR"tst-update_passwd/etc");
  if (r != 0)
    {
      fprintf(stderr, "update_passwd(<no change>) did return %i\n", r);
      return 1;
    }

  return 0;
}
