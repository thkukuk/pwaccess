// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <crypt.h>
#include <syslog.h>

#include "basics.h"
#include "files.h"

int
create_hash(const char *password, const char *prefix,
	    unsigned long count, char **hash, char **error)
{
  /* Strings returned by crypt_gensalt_rn will be no longer than this. */
  char salt[CRYPT_GENSALT_OUTPUT_SIZE];
  _cleanup_free_ struct crypt_data *cdata = NULL;
  char *sp;

  assert(password);
  assert(hash);

  sp = crypt_gensalt_rn(prefix, count, NULL, 0, salt, sizeof(salt));
  if (sp == NULL)
    return -errno;

  cdata = calloc(1, sizeof(*cdata));
  if (cdata == NULL)
    return -ENOMEM;

  sp = crypt_r(password, salt, cdata);
  if (sp == NULL)
    return -errno;

  if (!strneq(sp, prefix, strlen(prefix)))
    {
      /* crypt doesn't know the algorithm, error out */
      int r = -ENOSYS;
      if (error)
	{
	  if (asprintf (error, "Algorithm with prefix '%s' is not supported by the crypto backend.", prefix) < 0)
	    {
	      *error = NULL;
	      r = -ENOMEM;
	    }
	}
      explicit_bzero(cdata, sizeof(struct crypt_data));
      return r;
    }

  *hash = strdup(sp);
  explicit_bzero(cdata, sizeof(struct crypt_data));
  if (*hash == NULL)
    return -ENOMEM;

  return 0;
}
