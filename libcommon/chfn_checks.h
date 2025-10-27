// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

extern bool may_change_field(uid_t uid, char field);
extern bool chfn_check_string(const char *string, const char *illegal,
		              char **error);
