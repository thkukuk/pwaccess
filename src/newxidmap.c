// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <systemd/sd-varlink.h>

#include "basics.h"

struct status {
  bool success;
  char *error;
};

static void
status_free (struct status *var)
{
  var->error = mfree(var->error);
}

struct map_range {
  unsigned long upper; /* first ID inside the namespace */
  unsigned long lower; /* first ID outside the namespace */
  unsigned long count; /* Length of the inside and outside ranges */
};

static void
map_range_freep(struct map_range **var)
{
  if (!var || !*var)
    return;

  *var = mfree(*var);
}

static int
get_map_ranges(int ranges, char **argv, struct map_range **res)
{
  _cleanup_(map_range_freep) struct map_range *mappings = NULL;
  char *ep;

  assert(res);
  *res = NULL;

  mappings = calloc(ranges, sizeof(struct map_range));
  if (!mappings)
    {
      fprintf(stderr, "Out of memory!\n");
      return -ENOMEM;
    }

  /* Gather up the ranges from the command line */
  for (int i = 0; i < ranges; i++)
    {
      int j = i*3;

      errno = 0;
      mappings[i].upper = strtoul(argv[j], &ep, 10);
      if (errno == ERANGE || argv[j] == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse upper argument ('%s')\n", argv[j]);
	  return EINVAL;
	}

      errno = 0;
      mappings[i].lower = strtoul(argv[j+1], &ep, 10);
      if (errno == ERANGE || argv[j+1] == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse lower argument ('%s')\n", argv[j+1]);
	  return EINVAL;
	}

      errno = 0;
      mappings[i].count = strtoul(argv[j+2], &ep, 10);
      if (errno == ERANGE || argv[j] == ep || *ep != '\0')
	{
	  fprintf(stderr, "Cannot parse count argument ('%s')\n", argv[j]);
	  return EINVAL;
	}
    }
  *res = TAKE_PTR(mappings);
  return 0;
}

static int
connect_to_newidmapd(sd_varlink **ret, const char *socket, char **error)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  int r;

  r = sd_varlink_connect_address(&link, socket);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to connect to %s: %s",
                      socket, strerror(-r)) < 0)
          {
            error = NULL;
            r = -ENOMEM;
          }
      return r;
    }

  *ret = TAKE_PTR(link);
  return 0;
}

static void
print_usage(FILE *stream)
{
  fprintf(stream, "Usage: new"XID"map [<pid>|fd:<pidfd>] <"XID"> <lower"XID"> <count> [ <"XID"> <lower"XID"> <count> ] ... [--help] [--version]\n");
}

static void
print_help(void)
{
  fprintf(stdout, "new"XID"map - set "XID" mapping of a user namespace\n\n");
  print_usage(stdout);

  fputs("  -h, --help          Give this help list\n", stdout);
  fputs("  -v, --version       Print program version\n", stdout);
}

static void
print_error(void)
{
  fprintf (stderr, "Try `new"XID"map --help' for more information.\n");
}

int
main(int argc, char **argv)
{
  _cleanup_(status_free) struct status p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct status, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct status, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
  _cleanup_free_ char *error = NULL;
  sd_json_variant *result = NULL;
  const char *error_id = NULL;
  int ranges;
  _cleanup_(map_range_freep) struct map_range *mappings = NULL;
  pid_t arg_pid;
  char *ep;
  int r;

  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
          {"version",     no_argument,       NULL, 'v' },
          {"help",        no_argument,       NULL, 'h' },
          {NULL,          0,                 NULL, '\0'}
        };

      c = getopt_long (argc, argv, "vh",
                       long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
        case 'h':
          print_help();
          return 0;
        case 'v':
	  printf("new"XID"map (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_error();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc < 4)
    {
      fprintf(stderr, "new"XID"map: Not enough arguments.\n");
      print_error();
      return 1;
    }

  const char *pid_str = argv[0];
  if (strlen(pid_str) > 3 && startswith(pid_str, "fd:"))
    {
      fprintf(stderr, "'fd:<pid>' as argument is currently not supported\n");
      return EINVAL;
    }

  errno = 0;
  arg_pid = strtol(pid_str, &ep, 10);
  if (errno == ERANGE || arg_pid < -1 || pid_str == ep || *ep != '\0')
    {
      fprintf(stderr, "Cannot parse PID argument ('%s')\n", pid_str);
      return EINVAL;
    }

  ranges = (argc - 1) / 3;
  if ((ranges * 3) != (argc -1))
    {
      fprintf(stderr, "Number of arguments is wrong (not a multiple of 3 + 1)!\n");
      return EINVAL;
    }
  r = get_map_ranges(ranges, argv + 1, &mappings);
  if (r < 0)
    return -r;

  r = connect_to_newidmapd(&link, _VARLINK_NEWIDMAPD_SOCKET, &error);
  if (r < 0)
    {
      if (error)
	fprintf(stderr, "%s\n", error);
      else
	fprintf(stderr, "Cannot connect to newidmapd! (%s)\n", strerror(-r));

      return -r;
    }

  for (int i = 0; i < ranges; i++)
    {
      r = sd_json_variant_append_arraybo(&array,
					 SD_JSON_BUILD_PAIR_UNSIGNED("upper", mappings[i].upper),
					 SD_JSON_BUILD_PAIR_UNSIGNED("lower", mappings[i].lower),
					 SD_JSON_BUILD_PAIR_UNSIGNED("count", mappings[i].count));
      if (r < 0)
	{
	  fprintf(stderr, "Appending array failed: %s\n", strerror(-r));
	  return -r;
	}

    }

  r = sd_json_buildo(&params,
		     SD_JSON_BUILD_PAIR_INTEGER("PID", arg_pid),
		     SD_JSON_BUILD_PAIR_STRING("Map", XID"_map"),
		     SD_JSON_BUILD_PAIR_VARIANT("MapRanges", array));
  if (r < 0)
    {
      fprintf(stderr, "Failed to build param list: %s\n", strerror(-r));
      return -r;
    }

  //sd_json_variant_dump(params, SD_JSON_FORMAT_NEWLINE, stdout, NULL);

  r = sd_varlink_call(link, "org.openSUSE.newidmapd.WriteMappings", params, &result, &error_id);
  if (r < 0)
    {
      fprintf(stderr, "Failed to call WriteMappings method: %s\n",
	      strerror(-r));
      return -r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      fprintf(stderr, "Failed to parse JSON answer: %s", strerror(-r));
      return -r;
    }

  if (!isempty(error) || !isempty(error_id))
    {
      fprintf(stderr, "%s\n", p.error?p.error:error_id);
      return EIO;
    }

  return 0;
}
