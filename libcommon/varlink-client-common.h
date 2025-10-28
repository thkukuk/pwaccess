// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <security/pam_misc.h>

struct result {
  bool success;
  char *error;
};

extern struct pam_response *resp;

extern int connect_to_pwupdd(sd_varlink **ret, const char *socket,
		char **error);
extern int reply_callback(sd_varlink *link, sd_json_variant *parameters,
		const char *error, sd_varlink_reply_flags_t flags,
		void *userdata);


