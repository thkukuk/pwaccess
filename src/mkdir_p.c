/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2024, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

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

