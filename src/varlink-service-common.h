// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

extern void log_msg (int priority, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
extern void set_max_log_level (int level);

extern int vl_method_ping(sd_varlink *link, sd_json_variant *parameters,
		sd_varlink_method_flags_t flags, void *userdata);
extern int vl_method_set_log_level(sd_varlink *link,
		sd_json_variant *parameters, sd_varlink_method_flags_t flags,
		void *userdata);
extern int vl_method_get_environment(sd_varlink *link,
		sd_json_variant *parameters, sd_varlink_method_flags_t flags,
		void *userdata);
extern int vl_method_quit(sd_varlink *link, sd_json_variant *parameters,
		sd_varlink_method_flags_t flags, void *userdata);
