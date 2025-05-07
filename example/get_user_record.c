//SPDX-License-Identifier: GPL-2.0-or-later

#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>

#include "pwaccess.h"

#include "basics.h"

int
main(void)
{
  _cleanup_free_ char *error = NULL;
  _cleanup_(struct_passwd_freep) struct passwd *pw = NULL;
  _cleanup_(struct_shadow_freep) struct spwd *sp = NULL;
  bool complete = false;
  int r;

  r = pwaccess_get_user_record(getuid(), NULL, &pw, &sp, &complete, &error);
  if (r < 0)
    {
      if (error)
	fprintf (stderr, "%s\n", error);
      else
        fprintf (stderr, "get_user_record failed: %s\n", strerror(-r));
      return 1;
    }

  if (pw == NULL)
    {
      fprintf(stderr, "ERROR: no password entry found!\n");
      return 1;
    }

  printf("Name:     %s\n", pw->pw_name);
  printf("Password: %s\n", strna(sp?sp->sp_pwdp:pw->pw_passwd));
  printf("UID:      %i\n", pw->pw_uid);
  printf("GID:      %i\n", pw->pw_gid);
  printf("GECOS:    %s\n", strna(pw->pw_gecos));
  printf("Dir:      %s\n", strna(pw->pw_dir));
  printf("Shell:    %s\n", strna(pw->pw_shell));
  if (sp)
    {
      printf("LstChg:   %li\n", sp->sp_lstchg);
      printf("Min:      %li\n", sp->sp_min);
      printf("Max:      %li\n", sp->sp_max);
      printf("Warn:     %li\n", sp->sp_warn);
      printf("Inact:    %li\n", sp->sp_inact);
      printf("Expire:   %li\n", sp->sp_expire);
      printf("Flag:     %li\n", sp->sp_flag);
    }
  if (!complete)
    printf("For permission reasons the result is incomplete.\n");

  return 0;
}
