// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <pwd.h>
#include <shadow.h>

#include "basics.h"
#include "pwaccess.h"
#include "pam_unix_ng.h"
#include "files.h"

int
get_local_user_record(pam_handle_t *pamh, const char *user,
		      struct passwd **ret_pw, struct spwd **ret_sp)
{
  _cleanup_fclose_ FILE *fp = NULL;
  struct passwd pw;
  struct spwd sp;
  struct passwd *pw_ptr = NULL;
  struct spwd *sp_ptr = NULL;
  _cleanup_free_ char *pwbuf;
  long pwbufsize = 0;
  _cleanup_free_ char *spbuf;
  long spbufsize = 0;
  int r;

  assert(user);
  assert(ret_pw);
  assert(ret_sp);

  *ret_pw = NULL;
  *ret_sp = NULL;

  /* Get passwd entry */
  if ((fp = fopen("/etc/passwd", "r")) == NULL)
    return -errno;

  r = alloc_getxxnam_buffer(pamh, &pwbuf, &pwbufsize);
  if (r != PAM_SUCCESS)
    return r;

  /* Loop over all passwd entries */
  r = 0;
  while (r == 0)
    {
      r = fgetpwent_r(fp, &pw, pwbuf, pwbufsize, &pw_ptr);
      if (ret_pw != NULL)
	{
	  if(streq(pw_ptr->pw_name, user))
	    break;
	}
    }
  if (r != 0)
    return -errno;

  r = fclose(fp);
  fp = NULL;
  if (r < 0)
    return -errno;

  /* Get shadow entry */
  if ((fp = fopen("/etc/shadow", "r")) == NULL)
    return -errno;

  r = alloc_getxxnam_buffer(pamh, &spbuf, &spbufsize);
  if (r != PAM_SUCCESS)
    return r;

  /* Loop over all shadow entries */
  r = 0;
  while (r == 0)
    {
      r = fgetspent_r(fp, &sp, spbuf, spbufsize, &sp_ptr);
      if (ret_sp != NULL)
	{
	  if (streq(sp_ptr->sp_namp, user))
	    break;
	}
    }
  if (r != 0)
    return -errno;

  r = fclose(fp);
  fp = NULL;
  if (r < 0)
    return -errno;

  /* ret_pw != NULL -> pw contains valid entry, duplicate that */
  if (pw_ptr)
    {
      _cleanup_(struct_passwd_freep) struct passwd *tmp = NULL;

      tmp = calloc(1, sizeof(struct passwd));
      if (tmp == NULL)
	return -ENOMEM;

      tmp->pw_name = strdup(pw.pw_name);
      tmp->pw_passwd = strdup(strempty(pw.pw_passwd));
      tmp->pw_uid = pw.pw_uid;
      tmp->pw_gid = pw.pw_gid;
      tmp->pw_gecos = strdup(strempty(pw.pw_gecos));
      tmp->pw_dir = strdup(strempty(pw.pw_dir));
      tmp->pw_shell = strdup(strempty(pw.pw_shell));
      /* if any of the string pointer is NULL, strdup failed */
      if (!tmp->pw_name || !tmp->pw_passwd || !tmp->pw_gecos ||
	  !tmp->pw_dir || !tmp->pw_shell)
	return -ENOMEM;

      *ret_pw = TAKE_PTR(tmp);
    }
  if (sp_ptr)
    {
      _cleanup_(struct_shadow_freep) struct spwd *tmp;

      tmp = calloc(1, sizeof(struct spwd));
      if (tmp == NULL)
	return -ENOMEM;

      tmp->sp_namp = strdup(sp.sp_namp);
      tmp->sp_pwdp = strdup(strempty(sp.sp_pwdp));
      tmp->sp_lstchg = sp.sp_lstchg;
      tmp->sp_min = sp.sp_min;
      tmp->sp_max = sp.sp_max;
      tmp->sp_warn = sp.sp_warn;
      tmp->sp_inact = sp.sp_inact;
      tmp->sp_expire = sp.sp_expire;
      tmp->sp_flag = sp.sp_flag;

      if (!tmp->sp_namp || !tmp->sp_pwdp)
	return -ENOMEM;

      *ret_sp = TAKE_PTR(tmp);
    }

  return 0;
}
