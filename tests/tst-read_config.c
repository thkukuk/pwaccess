// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>

#include "basics.h"
#include "read_config.h"

static void
print_allow(const char *group, uid_t *list)
{
  printf("Group [%s]:", group);

  if (list == NULL)
    {
      fputs(" <none>\n", stdout);
      return;
    }

  for (size_t i = 0; list[i] != 0; i++)
    printf(" %u", list[i]);
  fputs("\n", stdout);

  return;
}

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

  print_allow("GetUserRecord", cfg.allow_get_user_record);
  print_allow("VerifyPassword", cfg.allow_verify_password);
  print_allow("ExpiredCheck", cfg.allow_expired_check);

  if (cfg.allow_get_user_record == NULL)
    {
      printf("GetUserRecord: UID of nobody not found!\n");
      return 1;
    }
  if (cfg.allow_get_user_record[0] != 65534)
    {
      printf("GetUserRecord: first UID is not nobody but '%u'!\n",
	     cfg.allow_get_user_record[0]);
      return 1;
    }
  if (cfg.allow_get_user_record[1] != 0)
    {
      printf("GetUserRecord: second entry is not 0 but '%u'!\n",
	     cfg.allow_get_user_record[1]);
      return 1;
    }

  if (cfg.allow_verify_password != NULL)
    {
      printf("VerifyPassword is not NULL!\n");
      return 1;
    }

  if (cfg.allow_expired_check != NULL)
    {
      printf("ExpiredCheck is not NULL!\n");
      return 1;
    }

  return 0;
}
