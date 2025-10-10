// SPDX-License-Identifier: BSD-2-Clause

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <shadow.h>
#include <sys/stat.h>

#include "basics.h"
#include "files.h"

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED (is_selinux_enabled()>0)
#else
#define SELINUX_ENABLED 0
#endif

#define MAX_LOCK_RETRIES 300 /* How often should we try to lock password file */

static int
lock_db(void)
{
  int retries = 0;
  int r;

  while((r = lckpwdf()) != 0 && retries < MAX_LOCK_RETRIES)
    {
      usleep(10000); /* 1/100 second */
      ++retries;
    }

  if (r < 0)
    {
      if (retries == MAX_LOCK_RETRIES)
	return -ENOLCK;
      else
	return -errno;
    }
  return 0;
}

static void
unlink_and_free_tempfilep(char **p)
{
  if (p == NULL || *p == NULL)
    return;

  /* If the file is created with mkstemp(), it will (almost always) change
     the suffix. Treat this as a sign that the file was successfully created.
     We ignore both the rare case where the original suffix is used and
     unlink failures. */
  if (!endswith(*p, ".XXXXXX"))
    (void) unlink(*p);

  *p = mfree(*p);
}

static inline void
umaskp(mode_t *u)
{
  umask(*u);
}

/* This is much like mkostemp() but is subject to umask(). */
static int
mkostemp_safe(char *pattern)
{
  _cleanup_(umaskp) mode_t _saved_umask_ = umask(0077);
  int r;

  r = mkostemp(pattern, O_CLOEXEC);

  if (r < 0)
    return -errno;
  else
    return r;
}

static int
update_passwd_locked(struct passwd *newpw, const char *etcdir)
{
  _cleanup_(unlink_and_free_tempfilep) char *tmpfn = NULL;
  _cleanup_free_ char *passwd_orig = NULL;
  _cleanup_free_ char *passwd_old = NULL;
  _cleanup_close_ int newfd = -EBADF;
  _cleanup_fclose_ FILE *oldf = NULL;
  _cleanup_fclose_ FILE *newf = NULL;
  struct passwd *pw; /* passwd struct obtained from fgetpwent() */
  struct stat st;
  int r;

  assert(newpw);
  assert(etcdir);

  if (asprintf(&passwd_orig, "%s/passwd", etcdir) < 0)
    return -ENOMEM;
  if (asprintf(&passwd_old, "%s/passwd-", etcdir) < 0)
    return -ENOMEM;
  if (asprintf(&tmpfn, "%s/.passwd.XXXXXX", etcdir) < 0)
    return -ENOMEM;

  if ((oldf = fopen(passwd_orig, "r")) == NULL)
    return -errno;

  if (fstat(fileno(oldf), &st) < 0)
    return -errno;

  newfd = mkostemp_safe(tmpfn);
  if (newfd < 0)
    return newfd; /* newfd == -errno */

  r = fchmod(newfd, st.st_mode);
  if (r < 0)
    return -errno;

  r = fchown(newfd, st.st_uid, st.st_gid);
  if (r < 0)
    return -errno;

#if 0 /* XXX */
  r = copy_xattr(pamh, passwd_orig, passwd_tmp);
  if (r > 0)
    return -r;
#endif

  newf = fdopen(newfd, "w+");
  if (newf == NULL)
    return -errno;

  int gotit = 0;
  /* Loop over all passwd entries */
  while ((pw = fgetpwent(oldf)) != NULL)
    {
      if(!gotit && streq(newpw->pw_name, pw->pw_name))
	{
	  int changed = 0;
	  if (!isempty(newpw->pw_passwd) && !streq(pw->pw_passwd, newpw->pw_passwd))
	    {
	      pw->pw_passwd = newpw->pw_passwd;
	      changed = 1;
	    }
	  if (!isempty(newpw->pw_shell) && !streq(pw->pw_shell, newpw->pw_shell))
	    {
	      pw->pw_shell = newpw->pw_shell;
	      changed = 1;
	    }
	  if (!isempty(newpw->pw_gecos) && !streq(pw->pw_gecos, newpw->pw_gecos))
	    {
	      pw->pw_gecos = newpw->pw_gecos;
	      changed = 1;
	    }
	  if (!isempty(newpw->pw_dir) && !streq(pw->pw_dir, newpw->pw_dir))
	    {
	      pw->pw_dir = newpw->pw_dir;
	      changed = 1;
	    }

	  if (!changed) /* nothing to change, change nothing */
	    return 0;

	  gotit = 1;
	}

      /* write the passwd entry to tmp file */
      r = putpwent(pw, newf);
      if (r < 0)
	return -errno;
    }

  r = fclose(oldf);
  oldf = NULL;
  if (r < 0)
    return -errno;

  r = fflush(newf);
  if (r < 0)
    return -errno;

  r = fsync(fileno(newf));
  if (r < 0)
    return -errno;

  r = fclose(newf);
  newf = NULL;
  if (r < 0)
    return -errno;

  unlink(passwd_old);
  r = link(passwd_orig, passwd_old);
  if (r < 0)
    return -errno;

  r = rename(tmpfn, passwd_orig);
  if (r < 0)
    return -errno;

  return 0;
}

int
update_passwd(struct passwd *newpw, const char *etcdir)
{
  _cleanup_free_ char *passwd_orig = NULL;
#ifdef WITH_SELINUX
  char *prev_context_raw = NULL;
#endif
  int r;

  if (!newpw)
    return -EINVAL;

  if (isempty(etcdir))
    etcdir = "/etc";

  /* XXX adjust lock if etcdir is not /etc */
  if (streq(etcdir, "/etc"))
    {
      r = lock_db();
      if (r < 0)
	return r;
    }

  if (asprintf(&passwd_orig, "%s/passwd", etcdir) < 0)
    return -ENOMEM;

#ifdef WITH_SELINUX
  if (SELINUX_ENABLED)
    {
      char *passwd_context_raw = NULL;

      if (getfilecon_raw(passwd_orig, &passwd_context_raw) < 0)
	return -errno;

      if (getfscreatecon_raw(&prev_context_raw) < 0)
	{
	  int saved_errno = errno;
	  freecon(passwd_context_raw);
	  return -saved_errno;
	}
      if (setfscreatecon_raw(passwd_context_raw) < 0)
	{
	  int saved_errno = errno;
	  freecon(passwd_context_raw);
	  freecon(prev_context_raw);
	  return -saved_errno;
	}
      freecon(passwd_context_raw);
    }
#endif

  r = update_passwd_locked(newpw, etcdir);

#ifdef WITH_SELINUX
  if (SELINUX_ENABLED)
    {
      if (setfscreatecon_raw(prev_context_raw) < 0)
	r = -errno;
      freecon(prev_context_raw);
    }
#endif

  /* XXX adjust lock if etcdir is not /etc */
  if (streq(etcdir, "/etc"))
    {
      if (ulckpwdf() != 0)
	return -errno;
    }

  return r;
}
