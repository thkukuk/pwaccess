//SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#define _unused_ __attribute__((unused))
#define _pure_ __attribute__((__pure__))
#define _const_ __attribute__((__const__))
#define _sentinel_ __attribute__((__sentinel__))

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_GENERIC(var, type, nullvalue)                       \
        ({                                                       \
                type *_pvar_ = &(var);                           \
                type _var_ = *_pvar_;                            \
                type _nullvalue_ = nullvalue;                    \
                *_pvar_ = _nullvalue_;                           \
                _var_;                                           \
        })
#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

static inline void freep(void *p) {
        *(void**)p = mfree(*(void**) p);
}

static inline void closep(int *fd) {
  if (*fd)
        close(*fd);
}

static inline void fclosep(FILE **f) {
  if (*f)
        fclose(*f);
}

#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_free_ _cleanup_(freep)


/* from string-util-fundamental.h */

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

static inline const char *strempty(const char *s) {
        return s ?:"";
}

static inline const char* strna(const char *s) {
        return s ?: "n/a";
}

static inline const char* stroom(const char *s) {
        return s ?: "Out of memory";
}

extern char *startswith(const char *s, const char *prefix) _pure_;
extern char *endswith(const char *s, const char *suffix) _pure_;

static inline bool isempty(const char *a) {
        return !a || a[0] == '\0';
}
