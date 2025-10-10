// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <pwd.h>
#include <shadow.h>

extern int update_passwd(struct passwd *newpw, const char *etcdir);

