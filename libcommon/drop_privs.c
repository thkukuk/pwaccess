// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "drop_privs.h"

int
drop_privs(void)
{
  /* drop gid */
  if (setgid(getgid()) != 0)
    return -errno;

  /* drop uid */
  if (setuid(getuid()) != 0)
    return -errno;

  /* Try to regain root. If this succeeds, we failed to drop privileges. */
  if (setuid(0) != -1)
    return -EPERM;

  return 0;
}

int
check_and_drop_privs(void)
{
  int r;

  if (geteuid() == getuid() &&
      getegid() == getgid())
    return 0;

  fprintf(stderr, "Binary has the setuid or setgid bit set, please remove it.\n");

  r = drop_privs();
  if (r < 0)
    {
      fprintf(stderr, "Dropping privileges failed: %s\n", strerror(-r));
      return r;
    }

  return 0;
}
