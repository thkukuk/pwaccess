//SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#define VERIFY_OK             0  /* password matches */
#define VERIFY_FAILED         1  /* password does not match */
#define VERIFY_CRYPT_DISABLED 2  /* salt got disabled in libcrypt */
#define VERIFY_CRYPT_INVALID  3  /* salt is not supported by libcrypt */

#include <pwd.h>

extern bool is_shadow(const struct passwd *pw);
extern int verify_password(const char *hash, const char *password, bool nullok);

