// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <crypt.h>
#include <syslog.h>
#include <security/pam_ext.h>

#include "basics.h"
#include "files.h"

int
create_hash(pam_handle_t *pamh, const char *password, char **hash)
{
  const char *algoid;
  int rounds = 0; /* XXX */
  /* Strings returned by crypt_gensalt_rn will be no longer than this. */
  char salt[CRYPT_GENSALT_OUTPUT_SIZE];
  _cleanup_free_ struct crypt_data *cdata = NULL;
  char *sp;

  assert(password);
  assert(hash);

  /* XXX add all the missing ones... */
  /* sha512 */
  algoid = "$6$";

  sp = crypt_gensalt_rn(algoid, rounds, NULL, 0, salt, sizeof(salt));
  if (sp == NULL)
    return -errno;

  cdata = calloc(1, sizeof(*cdata));
  if (cdata == NULL)
    return -ENOMEM;

  sp = crypt_r(password, salt, cdata);
  if (sp == NULL)
    return -errno;

  if (strneq(sp, algoid, strlen(algoid)))
    {
      /* crypt doesn't know the algorithm, error out */
      pam_syslog(pamh, LOG_ERR,
		 "Algorithm %s not supported by the crypto backend.",
		 algoid);
      explicit_bzero(cdata, sizeof(struct crypt_data));
      return -ENOSYS;
    }

  *hash = strdup(sp);
  explicit_bzero(cdata, sizeof(struct crypt_data));
  if (*hash == NULL)
    return -ENOMEM;

  return 0;
}
