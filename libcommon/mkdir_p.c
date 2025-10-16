// SPDX-License-Identifier: BSD-2-Clause

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "mkdir_p.h"

int
mkdir_p(const char *path, mode_t mode)
{
  if (path == NULL)
    return -EINVAL;

  if (mkdir(path, mode) == 0)
    return 0;

  if (errno == EEXIST)
    {
      struct stat st;

      /* Check if the existing path is a directory */
      if (stat(path, &st) != 0)
        return -errno;

      /* If not, fail with ENOTDIR */
      if (!S_ISDIR(st.st_mode))
        return -ENOTDIR;

      /* if it is a directory, return */
      return 0;
    }

  /* If it fails for any reason but ENOENT, fail */
  if (errno != ENOENT)
    return -errno;

  char *buf = strdup(path);
  if (buf == NULL)
    return -ENOMEM;

  int r = mkdir_p(dirname(buf), mode);
  free(buf);
  /* if we couldn't create the parent, fail, too */
  if (r < 0)
    return r;

  return mkdir(path, mode);
}

