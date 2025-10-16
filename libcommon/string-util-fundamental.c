/* SPDX-License-Identifier: LGPL-2.1-or-later */

// based on systemd v258

#include <assert.h>

#include "basics.h"

char *startswith(const char *s, const char *prefix) {
        size_t l;

        assert(s);
        assert(prefix);

        l = strlen(prefix);
        if (!strneq(s, prefix, l))
                return NULL;

        return (char*) s + l;
}

char* endswith(const char *s, const char *suffix) {
        size_t sl, pl;

        assert(s);
        assert(suffix);

        sl = strlen(s);
        pl = strlen(suffix);

        if (pl == 0)
                return (char*) s + sl;

        if (sl < pl)
                return NULL;

        if (!streq(s + sl - pl, suffix))
                return NULL;

        return (char*) s + sl - pl;
}
