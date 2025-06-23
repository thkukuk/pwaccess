//SPDX-License-Identifier: GPL-2.0-or-later

#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>

#include "pwaccess.h"

#include "basics.h"

int
main(int argc, char **argv)
{
  _cleanup_free_ char *error = NULL;
  bool pwchangeable = false;
  long daysleft = -1;
  int r;

  if (argc != 2)
    {
      fprintf(stderr, "Usage: check_expired <account>\n");
      return 1;
    }

  r = pwaccess_check_expired(argv[1], &daysleft, &pwchangeable, &error);
  if (r < 0)
    {
      if (error)
	fprintf(stderr, "%s\n", error);
      else
        fprintf(stderr, "check_expired failed: %s\n", strerror(-r));
      return 1;
    }

  printf("Expired: %i\n", r);

  printf("Days left: %li\n", daysleft);

  if (pwchangeable)
    fprintf(stdout, "Password can be changed.\n");
  else
    fprintf(stdout, "Password cannot be changed.\n");

  return 0;
}
