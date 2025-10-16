// SPDX-License-Identifier: BSD-2-Clause

#include <sys/prctl.h>

#include "no_new_privs.h"

bool
no_new_privs_enabled(void)
{
  /* The no_new_privs flag disables setuid at execve(2) time. */
  return (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
}
