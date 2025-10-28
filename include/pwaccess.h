//SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <pwd.h>
#include <shadow.h>
#include <stdint.h>
#include <stdbool.h>

#define PWACCESS_IS_NOT_RUNNING(r) (r == -ECONNREFUSED || r == -ENOENT || r == -ECONNRESET || r == -EACCES)

typedef enum {
  PWA_EXPIRED_NO = 0,          /* account is valid */
#define PWA_EXPIRED_NO         PWA_EXPIRED_NO
  PWA_EXPIRED_ACCT = 1,        /* account is expired */
#define PWA_EXPIRED_ACCT       PWA_EXPIRED_ACCT
  PWA_EXPIRED_CHANGE_PW = 2,   /* password is expired, change password */
#define PWA_EXPIRED_CHANGE_PW  PWA_EXPIRED_CHANGE_PW
  PWA_EXPIRED_PW = 3,          /* password is expired, password change not possible */
#define PWA_EXPIRED_PW         PWA_EXPIRED_PW
} pwa_expire_flag_t;

extern struct passwd *struct_passwd_free(struct passwd *var);
extern void struct_passwd_freep(struct passwd **var);

extern struct spwd *struct_shadow_free(struct spwd *var);
extern void struct_shadow_freep(struct spwd **var);

extern int pwaccess_check_expired(const char *user, long *daysleft,
				  bool *pwchangeable, char ** error);
extern int pwaccess_get_user_record(int64_t uid, const char *user,
				    struct passwd **pw, struct spwd **sp,
				    bool *complete, char **error);
extern int pwaccess_verify_password(const char *user, const char *password,
		                    bool nullok,
				    bool *ret_authenticated, char **error);
