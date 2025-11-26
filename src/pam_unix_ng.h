// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <stdint.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <time.h>

#define ARG_DEBUG	1 /* send info to syslog(3) */
#define ARG_QUIET	2 /* keep quiet about things */
#define ARG_NULLOK	4 /* allow blank passwords */
#define ARG_NONULL	8 /* don't allow blank passwords */

struct config_t
{
  /*
   * why is this called `ctrl`? The flags above have an ARG_ prefix.
   * maybe calling this flags or opts would be more suitable.
   * this could also be a candidate for an enum type.
   */
  uint32_t ctrl;
  uint32_t fail_delay;  /* sleep of milliseconds in case of auth failure */
  int minlen;           /* minimal length of new password */
  const char *crypt_prefix;  /* see man crypt(5) */
  unsigned long crypt_count; /* see man crypt(5) */
};

extern int parse_args(pam_handle_t *pamh, int flags, int argc,
		      const char **argv, struct config_t *cfg,
		      bool init_crypt);
extern int alloc_getxxnam_buffer(pam_handle_t *pamh,
				 char **buf, long *size);
extern int authenticate_user(pam_handle_t *pamh, uint32_t ctrl,
			     const char *user, const char *password,
			     bool *ret_authenticated, char **error);

extern int errno_to_pam(int e);

extern void log_authentication_failure(pam_handle_t *pamh, const char *user);

extern void log_runtime_ms(pam_handle_t *pamh, const char *type, int retval,
			   struct timespec start, struct timespec stop);
static inline uint64_t
timespec_diff_ms(struct timespec start, struct timespec stop)
{
  return ((stop.tv_sec - start.tv_sec) * 1000000000 + (stop.tv_nsec - start.tv_nsec)) / 1000 / 1000;
}
