// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <stdint.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define ARG_DEBUG	1 /* send info to syslog(3) */
#define ARG_QUIET	2 /* keep quiet about things */
#define ARG_NULLOK	4 /* allow blank passwords */

extern uint32_t parse_args (pam_handle_t *pamh, int flags,
			    int argc, const char **argv);
extern int alloc_getxxnam_buffer(pam_handle_t *pamh,
				 char **buf, long *size);
