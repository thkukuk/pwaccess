// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>

#include "basics.h"
#include "read_config.h"

int
main(int argc _unused_, char **argv _unused_)
{
  struct config_t cfg = {NULL, NULL, NULL};

  econf_err error = read_config(&cfg);

  if (error != ECONF_SUCCESS)
    {
      fprintf(stderr, "read_config failed: %s\n", econf_errString(error));
      return error;
    }

  /* XXX check values */

  return 0;
}
