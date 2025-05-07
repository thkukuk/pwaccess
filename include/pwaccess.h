//SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <pwd.h>
#include <shadow.h>
#include <stdint.h>

#define PWACCESS_IS_NOT_RUNNING(r) (r == -ECONNREFUSED || r == -ENOENT || r == -ECONNRESET || r == -EACCES)

extern struct passwd *struct_passwd_free(struct passwd *var);
extern void struct_passwd_freep(struct passwd **var);

extern struct spwd *struct_shadow_free(struct spwd *var);
extern void struct_shadow_freep(struct spwd **var);

extern int pwaccess_get_user_record(int64_t uid, const char *user,
				    struct passwd **pw, struct spwd **sp,
				    bool *complete, char **error);

