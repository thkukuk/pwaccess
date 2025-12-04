// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <unistd.h>

extern bool check_caller_perms(uid_t peer_uid, uid_t target_uid, 
		uid_t *allowed);
