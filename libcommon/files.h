// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <pwd.h>
#include <shadow.h>
#include <security/pam_modules.h>

extern int update_passwd(struct passwd *newpw, const char *etcdir);
extern int update_shadow(struct spwd *newsp, const char *etcdir);

extern int create_hash(const char *password, const char *prefix,
		unsigned long count, char **hash, char **error);
