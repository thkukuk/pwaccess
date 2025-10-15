// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <pwd.h>
#include <shadow.h>
#include <security/pam_modules.h>

extern int get_local_user_record(pam_handle_t *pamh, const char *user,
		struct passwd **ret_pw, struct spwd **ret_sp);
extern int update_passwd(struct passwd *newpw, const char *etcdir);

