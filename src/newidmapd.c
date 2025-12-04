// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <pwd.h>
#include <getopt.h>
#include <syslog.h>
#include <libeconf.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>

#include "basics.h"
#include "mkdir_p.h"
#include "varlink-service-common.h"

#include "varlink-org.openSUSE.newidmapd.h"

#define USEC_PER_SEC  ((uint64_t) 1000000ULL)
/* event loop which quits after 30 seconds idle time */
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

#define UID_MAX ((uid_t)-1)

static int socket_activation = false;

/* XXX unify with newxidmap.c */
struct map_range {
  int64_t upper; /* first ID inside the namespace */
  int64_t lower; /* first ID outside the namespace */
  int64_t count; /* Length of the inside and outside ranges */
};

static void
map_range_freep(struct map_range **var)
{
  if (!var || !*var)
    return;

  *var = mfree(*var);
}

struct parameters {
  pid_t pid;
  char *map; /* see varlink interface definition for valid names */
  int nranges;
  struct map_range *mappings;
  sd_json_variant *content_map_ranges;
};

static void
parameters_free(struct parameters *var)
{
  var->map = mfree(var->map);
  var->nranges = 0;
  map_range_freep(&(var->mappings));
  var->content_map_ranges = sd_json_variant_unref(var->content_map_ranges);
}

static int
open_pidfd(pid_t pid)
{
  _cleanup_free_ char *proc_dir = NULL;
  int proc_dir_fd;

  if (asprintf(&proc_dir, "/proc/%u/", pid) == -1)
    {
      log_msg(LOG_ERR, "Out of memory!");
      return -ENOMEM;
    }

  proc_dir_fd = open(proc_dir, O_DIRECTORY);
  if (proc_dir_fd < 0)
    {
      log_msg(LOG_ERR, "Open proc directory (%s) failed: %m\n", proc_dir);
      return -errno;
    }
  return proc_dir_fd;
}

static bool
verify_range(uid_t uid, int64_t start, int64_t count, const struct map_range mapping)
{
  if (mapping.count == 0)
    return false;

  /* Allow a process to map its own uid */
  if ((mapping.count == 1) && (uid == mapping.lower))
    return true;

  /* first ID outside namespace must be between start and start+count */
  if (mapping.lower < start || mapping.lower >= start+count)
    return false;

  /* last ID outside must be smaller than start+count.
     -1 because lower is already the first ID. */
  if ((mapping.lower+mapping.count-1) < (start+count))
    return true;

  return false;
}

/* result < 0: error (-errno)
   0 : range is valid
   1 : range is invalid */
static int
verify_ranges(uid_t uid, int nranges, const struct map_range *mappings, const char *map)
{
  const char *subid_file = NULL;
  _cleanup_(econf_freeFilep) econf_file *econf = NULL;
  econf_err error;
  const char *user;
  _cleanup_free_ char *val = NULL;
  long start, count;

  struct passwd *pw = getpwuid(uid);
  if (pw == NULL)
    return -ENODATA;
  user = pw->pw_name;

  if (streq(map, "uid_map"))
    subid_file = "/etc/subuid";
  else if (streq(map, "gid_map"))
    subid_file = "/etc/subgid";
  else
    {
      log_msg(LOG_ERR, "Unknown map name: '%s'", map);
      return -EINVAL;
    }

  error = econf_readFile(&econf, subid_file, ":", "#");
  if (error != ECONF_SUCCESS)
    {
      log_msg(LOG_ERR, "Cannot open %s: %s", subid_file, econf_errString(error));
      if (error == ECONF_NOFILE)
	return -ENOENT;
      else
	return -EIO;
    }

  error = econf_getStringValue(econf, NULL, user, &val);
  if (error != ECONF_SUCCESS)
    {
      if (error == ECONF_NOKEY)
	log_msg(LOG_ERR, "Mapping range for user '%s' not found in %s", user, subid_file);
      else
	log_msg(LOG_ERR, "Error retrieving key '%s': %s", user, econf_errString(error));
      return -ENODATA;
    }

  char *cp = strchr(val, ':');
  if (cp == NULL)
    {
      log_msg(LOG_ERR, "Invalid format for user %s in %s: %s", user, subid_file, val);
      return -EINVAL;
    }

  *cp++='\0';

  char *ep = NULL;
  errno = 0;
  start = strtol(val, &ep, 10);
  if (errno == ERANGE || start < -1 || start > UID_MAX || val == ep || *ep != '\0')
    {
      log_msg(LOG_ERR, "Cannot parse 'start' value (%s,%s,%s)", subid_file, user, val);
      return -EINVAL;
    }
  errno = 0;
  count = strtol(cp, &ep, 10);
  if (errno == ERANGE || count < -1 || count >= (UID_MAX - start) || cp == ep || *ep != '\0')
    {
      log_msg(LOG_ERR, "Cannot parse 'count' value (%s,%s,%s)", subid_file, user, cp);
      return -EINVAL;
    }

  log_msg(LOG_DEBUG, "%s: user=%s, start=%li, count=%li", subid_file, user, start, count);

  for (int i = 0; i < nranges; i++)
    {
      if (!verify_range(uid, start, count, mappings[i]))
	return 1;
    }

  return 0;
}

static int
write_mapping(int proc_dir_fd, int nranges, const struct map_range *mappings,
	      const char *map)
{
  _cleanup_free_ char *res = NULL;
  _cleanup_close_ int fd = -EBADF;
  int r;

  res = strdup("");
  if (res == NULL)
    {
      log_msg(LOG_ERR, "Out of memory!");
      return -ENOMEM;
    }

  for (int i = 0; i < nranges; i++)
    {
      _cleanup_free_ char *old_res = res;

      if (asprintf(&res, "%s%lu %lu %lu\n", old_res, mappings[i].upper,
		   mappings[i].lower, mappings[i].count) == -1)
	{
	  log_msg(LOG_ERR, "Out of memory!");
	  return -ENOMEM;
	}
    }

  log_msg(LOG_DEBUG, "mapping string: '%s'", res);

  /* Write the mapping to the mapping file */
  fd = openat(proc_dir_fd, map, O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
  if (fd < 0)
    {
      r = -errno;
      log_msg(LOG_ERR, "Failed to open '%s': %s",
	      map, strerror(-r));
      return r;
    }
  if (write(fd, res, strlen(res)) == -1)
    {
      r = -errno;
      log_msg(LOG_ERR, "Failed to write to '%s': %s",
	      map, strerror(-r));
      return r;
    }
  if (close(fd) != 0 && errno != EINTR)
    {
      r = -errno;
      log_msg(LOG_ERR, "Failed to close '%s': %s",
	      map, strerror(-r));
      return r;
    }
  return 0;
}

static int
vl_method_write_mappings(sd_varlink *link, sd_json_variant *parameters,
			 sd_varlink_method_flags_t _unused_(flags),
			 void _unused_(*userdata))
{
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
  _cleanup_(parameters_free) struct parameters p = {
    .pid = 0,
    .map = NULL,
    .nranges = 0,
    .mappings = NULL,
    .content_map_ranges = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "PID",       SD_JSON_VARIANT_INTEGER,  sd_json_dispatch_int,    offsetof(struct parameters, pid), SD_JSON_MANDATORY},
    { "Map",       SD_JSON_VARIANT_STRING,   sd_json_dispatch_string, offsetof(struct parameters, map), SD_JSON_NULLABLE},
    { "MapRanges", SD_JSON_VARIANT_ARRAY,    sd_json_dispatch_variant, offsetof(struct parameters, content_map_ranges), SD_JSON_MANDATORY},
    {}
  };
  _cleanup_close_ int proc_dir_fd = -EBADF;
  uid_t peer_uid;
  gid_t peer_gid;
  int r;

  log_msg(LOG_INFO, "Varlink method \"WriteMappings\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r < 0)
    {
      log_msg(LOG_ERR, "WriteMappings request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  if (isempty(p.map))
    {
      log_msg(LOG_ERR, "No map name provided.");
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "No 'Map' entry provided."));
    }
  if (!streq(p.map, "uid_map") && !streq(p.map, "gid_map"))
    {
      log_msg(LOG_ERR, "Map name is neither 'uid_map' nor 'gid_map'.");
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Unknown map name provided."));
    }

  if (!sd_json_variant_is_array(p.content_map_ranges))
    {
      fprintf(stderr, "JSON 'MapRanges' is no array!\n");
      return -EINVAL;
    }

  size_t nranges = sd_json_variant_elements(p.content_map_ranges);
  /* 340 entries is the kernel limit since 4.16 */
  if (nranges > 340)
    {
      log_msg(LOG_ERR, "Too many MapRanges entries: %i, limit is 340", p.nranges);
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Entry 'MapRanges' has too many entries (>340)"));
    }
  p.nranges = nranges;
  p.mappings = calloc(p.nranges, sizeof(struct map_range));
  if (p.mappings == NULL)
    {
      log_msg(LOG_ERR, "Out of memory!");
      return -ENOMEM;
    }

  for (int i = 0; i < p.nranges; i++)
    {
      struct map_range e = {
        .upper = -1,
        .lower = -1,
	.count = -1,
      };
      static const sd_json_dispatch_field dispatch_entry_table[] = {
        { "upper", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_int64, offsetof(struct map_range, upper), SD_JSON_MANDATORY },
        { "lower", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_int64, offsetof(struct map_range, lower), SD_JSON_MANDATORY },
        { "count", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_int64, offsetof(struct map_range, count), SD_JSON_MANDATORY },
        {}
      };

      sd_json_variant *entry = sd_json_variant_by_index(p.content_map_ranges, i);
      if (!sd_json_variant_is_object(entry))
        {
          log_msg(LOG_ERR, "entry is no object!");
	  return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InvalidParameter",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Entry 'MapRanges' is no object"));
        }

      r = sd_json_dispatch(entry, dispatch_entry_table, SD_JSON_ALLOW_EXTENSIONS, &e);
      if (r < 0)
        {
	  log_msg(LOG_ERR, "Failed to parse JSON map_ranges entry: %s",
		  strerror(-r));
	  return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Failed to parse MapRanges object"));
        }

      if (e.upper < 0 || e.upper > UID_MAX ||
	  e.lower < 0 || e.lower > UID_MAX ||
	  e.count < 1 || e.count >= (UID_MAX - e.upper))
	{
	  log_msg(LOG_ERR, "Invalid map_ranges upper=%" PRIi64 ", lower=%" PRIi64 ", count=%" PRIi64,
		  e.upper, e.lower, e.count);
	  return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InternalError",
				    SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				    SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Failed to parse MapRanges object"));
	}

      log_msg(LOG_DEBUG, "map_ranges[%i] (%s): upper=%" PRIi64 ", lower=%" PRIi64 ", count=%" PRIi64, i, p.map, e.upper, e.lower, e.count);
      p.mappings[i] = e;
    }

  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  r = sd_varlink_get_peer_gid(link, &peer_gid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer GID: %s", strerror(-r));
      return r;
    }

  proc_dir_fd = open_pidfd(p.pid);
  if (proc_dir_fd < 0)
    return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InternalError",
			      SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
			      SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Cannot open '/proc/<pid>'"));

  /* Get the effective uid and effective gid of the target process */
  struct stat st;
  r = fstat(proc_dir_fd, &st);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Could not stat proc directory: %s", strerror(-r));
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Cannot access '/proc/<pid>'"));
    }
  if (st.st_uid != peer_uid || st.st_gid != peer_gid)
    {
      log_msg(LOG_ERR, "PID %i is owned by a different user: peer_uid=%u st_uid=%u peer_gid=%u st_gid=%u",
	      p.pid, peer_uid, st.st_uid, peer_gid, st.st_gid);
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.PermissionDenied",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "PID is owned by a different user"));
    }

  r = verify_ranges(peer_uid, p.nranges, p.mappings, p.map);
  if (r < 0)
    {
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.InvalidParameter",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Mapping ranges are not correct"));
    }
  if (r > 0)
    {
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.PermissionDenied",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Mapping ranges are not correct"));
    }

  r = write_mapping(proc_dir_fd, p.nranges, p.mappings, p.map);
  if (r < 0)
    {
      return sd_varlink_errorbo(link, "org.openSUSE.newidmapd.PermissionDenied",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Cannot write to '/proc/<pid>/<map>'"));
    }

  return sd_varlink_replybo(link,
                            SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

/* Send a messages to systemd daemon, that inicialization of daemon
   is finished and daemon is ready to accept connections. */
static void
announce_ready (void)
{
  int r = sd_notify (0, "READY=1\n"
		     "STATUS=Processing requests...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(READY) failed: %s", strerror(-r));
}

static void
announce_stopping (void)
{
  int r = sd_notify (0, "STOPPING=1\n"
		     "STATUS=Shutting down...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(STOPPING) failed: %s", strerror(-r));
}

static int
varlink_event_loop_with_idle(sd_event *e, sd_varlink_server *s)
{
  int r, code;

  for (;;)
    {
      r = sd_event_get_state(e);
      if (r < 0)
	return r;
      if (r == SD_EVENT_FINISHED)
	break;

      r = sd_event_run(e, DEFAULT_EXIT_USEC);
      if (r < 0)
	return r;

      if (r == 0 && (sd_varlink_server_current_connections(s) == 0))
	sd_event_exit(e, 0);
    }

  r = sd_event_get_exit_code(e, &code);
  if (r < 0)
    return r;

  return code;
}

static int
run_varlink (void)
{
  int r;
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;

  r = mkdir_p(_VARLINK_NEWIDMAPD_SOCKET_DIR, 0755);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create directory '"_VARLINK_NEWIDMAPD_SOCKET_DIR"' for Varlink socket: %s",
	      strerror(-r));
      return r;
    }

  r = sd_event_new (&event);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to create new event: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_new (&varlink_server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_INPUT_SENSITIVE);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to allocate varlink server: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_description (varlink_server, "newidmapd");
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to set varlink server description: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_info (varlink_server, NULL, PACKAGE" (newidmapd)",
				  VERSION, "https://github.com/thkukuk/newidmapd");
  if (r < 0)
    return r;

  r = sd_varlink_server_add_interface (varlink_server, &vl_interface_org_openSUSE_newidmapd);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to add interface: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_bind_method_many (varlink_server,
					  "org.openSUSE.newidmapd.WriteMappings",  vl_method_write_mappings,
					  "org.openSUSE.newidmapd.GetEnvironment", vl_method_get_environment,
					  "org.openSUSE.newidmapd.Ping",           vl_method_ping,
					  "org.openSUSE.newidmapd.Quit",           vl_method_quit,
					  "org.openSUSE.newidmapd.SetLogLevel",    vl_method_set_log_level);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind Varlink methods: %s",
	      strerror(-r));
      return r;
    }

  sd_varlink_server_set_userdata (varlink_server, event);

  r = sd_varlink_server_attach_event (varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to attach to event: %s", strerror (-r));
      return r;
    }

  r = sd_varlink_server_listen_auto (varlink_server);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to listen: %s", strerror (-r));
      return r;
    }


  if (!socket_activation)
    {
      r = sd_varlink_server_listen_address(varlink_server, _VARLINK_NEWIDMAPD_SOCKET, 0666);
      if (r < 0)
	{
	  log_msg (LOG_ERR, "Failed to bind to Varlink socket: %s", strerror (-r));
	  return r;
	}
    }

  announce_ready();
  if (socket_activation)
    r = varlink_event_loop_with_idle(event, varlink_server);
  else
    r = sd_event_loop(event);
  announce_stopping();

  return r;
}

static void
print_help (void)
{
  printf("newidmapd - manage passwd and shadow\n");

  printf("  -s, --socket   Activation through socket\n");
  printf("  -d, --debug    Debug mode\n");
  printf("  -v, --verbose  Verbose logging\n");
  printf("  -?, --help     Give this help list\n");
  printf("      --version  Print program version\n");
}

int
main (int argc, char **argv)
{
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"socket", no_argument, NULL, 's'},
          {"debug", no_argument, NULL, 'd'},
          {"verbose", no_argument, NULL, 'v'},
          {"version", no_argument, NULL, '\255'},
          {"usage", no_argument, NULL, '?'},
          {"help", no_argument, NULL, 'h'},
          {NULL, 0, NULL, '\0'}
        };


      c = getopt_long (argc, argv, "sdvh?", long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 's':
	  socket_activation = true;
	  break;
        case 'd':
	  set_max_log_level(LOG_DEBUG);
          break;
        case '?':
        case 'h':
          print_help ();
          return 0;
        case 'v':
	  set_max_log_level(LOG_INFO);
          break;
        case '\255':
          fprintf (stdout, "newidmapd (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_help ();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf (stderr, "Try `newidmapd --help' for more information.\n");
      return 1;
    }

  log_msg (LOG_INFO, "Starting newidmapd (%s) %s...", PACKAGE, VERSION);

  int r = run_varlink ();
  if (r < 0)
    {
      log_msg (LOG_ERR, "ERROR: varlink loop failed: %s", strerror (-r));
      return -r;
    }

  log_msg (LOG_INFO, "newidmapd stopped.");

  return 0;
}
