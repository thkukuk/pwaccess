/*
   Copyright (C) Nalin Dahyabhai <nalin@redhat.com> 2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
*/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "basics.h"

/* Simple program to see if dlopen() would succeed. */
int main(int argc, char **argv)
{
  int i;
  int rc;
  struct stat st;
  _cleanup_(freep) char *buf = NULL;

  for (i = 1; i < argc; i++) {
    if (dlopen(argv[i], RTLD_NOW)) {
      fprintf(stdout, "dlopen() of \"%s\" succeeded.\n",
              argv[i]);
    } else {
      rc = asprintf(&buf, "./%s", argv[i]);
      if (rc >= 0 && (stat(buf, &st) == 0) && dlopen(buf, RTLD_NOW)) {
        fprintf(stdout, "dlopen() of \"./%s\" "
                "succeeded.\n", argv[i]);
      } else {
        fprintf(stdout, "dlopen() of \"%s\" failed: "
                "%s\n", argv[i], dlerror());
        return 1;
      }
    }
  }
  return 0;
}
