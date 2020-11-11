#ifndef CHEZ_BOOT_H
#define CHEZ_BOOT_H

#include "types.h"
#include <limits.h>

typedef struct {
  INT fd;
  iptr len; /* 0 => unknown */
  /* Non-null iff contents are buffered - in which case len > 0
   * it is possible for contents to be NULL even if len > 0,
   * if, for example, we ran out of memory allocating space for
   * contents.
   */
  char *contents;
  iptr offset;
  IBOOL need_check, close_after;
  char path[PATH_MAX];
} boot_desc;

#define MAX_BOOT_FILES 10

void load(ptr tc, iptr n, IBOOL base);
IBOOL find_boot(const char *name,
                const char *ext,
                IBOOL direct_pathp,
                int fd,
                IBOOL errorp);



#endif /* CHEZ_BOOT_H */
