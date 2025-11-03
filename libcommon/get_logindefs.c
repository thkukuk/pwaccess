// SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <libeconf.h>

#include "basics.h"
#include "get_logindefs.h"

long
get_logindefs_num(const char *key, long def)
{
  _cleanup_(econf_freeFilep) econf_file *key_file = NULL;
  int32_t val;
  econf_err error;

  error = econf_readConfig(&key_file,
                           NULL /* project */,
                           _PATH_VENDORDIR /* usr_conf_dir */,
                           "login" /* config_name */,
                           "defs" /* config_suffix */,
                           "= \t" /* delim */,
                           "#" /* comment */);
  if (error != ECONF_SUCCESS)
    {
      fprintf(stderr, "Cannot parse login.defs: %s\n", econf_errString(error));
      return def;
    }

  error = econf_getIntValueDef (key_file, NULL, key, &val, def);
  if (error != ECONF_SUCCESS)
    {
      fprintf(stderr, "Error reading '%s': %s\n", key,
              econf_errString(error));
      return def;
    }

  return val;
}

