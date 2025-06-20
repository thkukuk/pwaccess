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
  bool authenticated = false;
  bool nullok = true;
  int r;

  if (argc < 2)
    {
      fprintf(stderr, "Usage: verify_password <account> [password]\n");
      return 1;
    }

  r = pwaccess_verify_password(argv[1], argv[2], nullok,
			       &authenticated, &error);
  if (r < 0)
    {
      if (error)
	fprintf(stderr, "%s\n", error);
      else
        fprintf(stderr, "verify_password failed: %s\n", strerror(-r));
      return 1;
    }

  if (authenticated)
    fprintf(stdout, "Access granted.\n");
  else
    {
      fprintf(stderr, "Access denied!\n");
      return 1;
    }

  return 0;
}
