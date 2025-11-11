
#define WITH_SELINUX 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

static const char *
selinux_status(void)
{
#ifdef WITH_SELINUX
  if (is_selinux_enabled() > 0)
    {
      int r = security_getenforce();
      switch (r)
        {
        case 1:
          return "enforcing";
          break;
        case 0:
          return "permissive";
          break;
        default:
          fprintf(stderr, "selinux error: %s\n",
		  strerror(errno));
          return "error";
          break;
        }
    }
  else
    return "off";
#else
  return "not available";
#endif
}

int
main(void)
{
  char *secon = NULL;
  int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  const char *sestatus = selinux_status();

  printf("🔎 Process Security Information\n");
  printf("-------------------------------\n");
  printf("Real UID:          %d\n", getuid());
  printf("Effective UID:     %d\n", geteuid());
  printf("Real GID:          %d\n", getgid());
  printf("Effective GID:     %d\n", getegid());
  printf("SELinux Status:    %s\n", sestatus);
  if (getcon(&secon) == 0)
    {
      printf("SELinux Context:   %s\n",   secon);
      freecon(secon); /* Free the memory allocated by getcon() */
    }
  else
    printf("SELinux Context:   %s\n", strerror(errno));
  printf("NoNewPrivs Status: %s\n", no_new_privs==0?"off":"on");

  getchar();

  return 0;
}
