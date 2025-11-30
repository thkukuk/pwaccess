// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "basics.h"

/* paths to check for setuid binaries or binaries with
   capabilities */
const char *search_paths[] = {
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/libexec",
    NULL
};

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: scan-caps [path]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "scan-caps - scan system for binaries with capabilities\n\n");

  print_usage(stdout);

  fputs("  -h, --help             Give this help list\n", stdout);
  fputs("  -v, --version          Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `scan-caps --help' for more information.\n");
}

static void
free_cap_text(char **p)
{
  if (p == NULL || *p == NULL)
    return;

  cap_free(*p);

  *p = NULL;
}

/* Checks a specific file for setuid, setgid, or capabilities */
static int
check_file(const char *file, struct stat st)
{
    _cleanup_(free_cap_text) char *caps_text = NULL;
    cap_t caps;
    int is_suid = 0;
    int is_sgid = 0;
    int has_caps = 0;
    int r;

    /* check regular files only */
    if (!S_ISREG(st.st_mode))
      return 0;

    if (st.st_mode & S_ISUID)
      is_suid = 1;

    if (st.st_mode & S_ISGID)
      is_sgid = 1;

    /* cap_get_file returns NULL if the file has no capabilities or on error */
    caps = cap_get_file(file);
    if (caps)
      {
        /* We have a cap object, but we need to ensure it's not empty */
        caps_text = cap_to_text(caps, NULL);
        if (caps_text && strlen(caps_text) > 0)
	  has_caps = 1;
        cap_free(caps);
      }
    else if (errno != ENODATA)
      {
	r = -errno;
	fprintf(stderr, "cap_get_file(%s) failed: %s\n", file, strerror(-r));
	return r;
      }

    if (is_suid || is_sgid || has_caps)
      {
        printf("Found: %s [", file);
        if (is_suid)
	  printf(" SUID ");
        if (is_sgid)
	  printf(" SGID ");
        if (has_caps)
	  printf(" CAP: %s ", caps_text);
        printf("]\n");
      }

    return 0;
}

/* Recursively walks a directory */
static int
walk_directory(const char *dir_path)
{
  DIR *dir;
  struct dirent *entry;
  struct stat st;
  int r;

  if (!(dir = opendir(dir_path)))
    {
      r = -errno;
      fprintf(stderr, "Cannot open directory '%s': %s\n",
	      dir_path, strerror(-r));
      return r;
    }

  while ((entry = readdir(dir)) != NULL)
    {
      _cleanup_free_ char *path = NULL;

      /* Skip . and .. */
      if (streq(entry->d_name, ".") || streq(entry->d_name, ".."))
	continue;

      if (asprintf(&path, "%s/%s", dir_path, entry->d_name) < 0)
	return -ENOMEM;

      /* Don't follow symlinks */
      r = lstat(path, &st);
      if (r < 0)
	{
	  r = -errno;
	  fprintf(stderr, "lstat(%s) failed: %s\n", path, strerror(-r));
	  return r;
	}

      if (S_ISLNK(st.st_mode))
	continue;

      if (S_ISDIR(st.st_mode))
	{
	  r = walk_directory(path);  /* Recurse into subdirectory */
	  if (r < 0)
	    return r;
	}
      else
	{
	  r = check_file(path, st);
	  if (r < 0)
	    return r;
	}
    }
  closedir(dir);

  return 0;
}

int
main(int argc, char **argv)
{
  int r;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"help",        no_argument,       NULL, 'h' },
          {"version",     no_argument,       NULL, 'v' },
	  {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "hv",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 'h':
          print_help();
          return 0;
        case 'v':
          printf("scan-caps (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_error();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  printf("🔎 Scanning for binaries with setuid, setgid, or capabilities...\n");
  printf("----------------------------------------------------------------\n");

  const char **scan_list = (argc > 0) ? (const char **)argv : search_paths;

  for (int i = 0; scan_list[i] != NULL; i++)
    {
      // If scanning argv, ensure we stop exactly at argc to match original logic
      // (Standard C guarantees argv[argc] is NULL, but this is defensively safe)
      if (argc > 0 && i >= argc) break;

      r = walk_directory(scan_list[i]);
      if (r < 0)
        {
          printf("Scan aborted.\n");
          return -r;
        }
    }

  printf("----------------------------------------------------------------\n");
  printf("Scan complete.\n");

  return 0;
}
