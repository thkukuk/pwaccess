// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <libeconf.h>

struct config_t {
  uid_t *allow_get_user_record;
  uid_t *allow_verify_password;
  uid_t *allow_expired_check;
};

extern econf_err read_config(struct config_t *cfg);
