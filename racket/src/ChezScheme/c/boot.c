#include "boot.h"

#include <sys/stat.h>
#include <fcntl.h>

#include "system.h"

static boot_desc bd[MAX_BOOT_FILES];

// Defined in scheme.c
extern IBOOL verbose;
extern INT boot_count;

/* locally defined functions */
static octet get_u8 (INT fd);
static uptr get_uptr (INT fd, uptr *pn);
static INT get_string (INT fd, char *s, iptr max, INT *c);
static void check_boot_file_state (const char *who);
static IBOOL check_prefix(int fd, const char *prefix, size_t len);
static IBOOL next_path (char *path, const char *name, const char *ext, const char **sp, const char **dsp);

static IBOOL check_prefix(int fd, const char *prefix, size_t len) {
  char *buf = (char *) alloca(len);
  const size_t bytes_read = read(fd, buf, len);

  if (bytes_read != len)
    return 0;

  return memcmp(buf, prefix, len) == 0;
}

static IBOOL check_boot(int fd, IBOOL verbose, const char *path) {
  uptr n = 0;
  const char header[] = {fasl_type_header, 0, 0, 0, 'c', 'h', 'e', 'z'};

  /* check for magic number in the prefix of fd */
  if (!check_prefix(fd, header, 8)) {
    if (verbose)
      fprintf(stderr, "malformed fasl-object header in %s\n", path);
    CLOSE(fd);
    return 0;
  }

  /* check version */
  if (get_uptr(fd, &n) != 0) {
    if (verbose)
      fprintf(stderr, "unexpected end of file on %s\n", path);
    CLOSE(fd);
    return 0;
  }

  if (n != scheme_version) {
    if (verbose) {
      fprintf(stderr, "%s is for Version %s; ", path, S_format_scheme_version(n));
      /* use separate fprintf since S_format_scheme_version returns static string */
      fprintf(stderr, "need Version %s\n", S_format_scheme_version(scheme_version));
    }
    CLOSE(fd);
    return 0;
  }

  /* check machine type */
  if (get_uptr(fd, &n) != 0) {
    if (verbose)
      fprintf(stderr, "unexpected end of file on %s\n", path);
    CLOSE(fd);
    return 0;
  }

  if (n != machine_type) {
    if (verbose)
      fprintf(stderr, "%s is for machine-type %s; need machine-type %s\n", path,
              S_lookup_machine_type(n), S_lookup_machine_type(machine_type));
    CLOSE(fd);
    return 0;
  }

  return 1;
}

static void check_dependencies_header(int fd, const char *path) {
  if (get_u8(fd) != '(') {  /* ) */
    fprintf(stderr, "malformed boot file %s\n", path);
    CLOSE(fd);
    S_abnormal_exit();
  }
}

static void finish_dependencies_header(int fd, const char *path, int c) {
  while (c != ')') {
    if (c < 0) {
      fprintf(stderr, "malformed boot file %s\n", path);
      CLOSE(fd);
      S_abnormal_exit();
    }
    c = get_u8(fd);
  }
}

IBOOL find_boot(const char *name,
                const char *ext,
                IBOOL direct_pathp,
                int fd,
                IBOOL errorp) {
  char pathbuf[PATH_MAX], buf[PATH_MAX];
  uptr n = 0;
  INT c;
  const char *path;
  char *expandedpath;

  if ((fd != -1) || direct_pathp || S_fixedpathp(name)) {
    if (strlen(name) >= PATH_MAX) {
      fprintf(stderr, "boot-file path is too long %s\n", name);
      S_abnormal_exit();
    }

    path = name;

    if (fd == -1) {
      expandedpath = S_malloc_pathname(path);
      fd = OPEN(expandedpath, O_BINARY|O_RDONLY, 0);
      free(expandedpath);
    }

    if (fd == -1) {
      if (errorp) {
        fprintf(stderr, "cannot open boot file %s\n", path);
        S_abnormal_exit();
      } else {
        if (verbose) fprintf(stderr, "trying %s...cannot open\n", path);
        return 0;
      }
    }
    if (verbose) fprintf(stderr, "trying %s...opened\n", path);

    if (!check_boot(fd, 1, path))
      S_abnormal_exit();
  } else {
    const char *sp = Sschemeheapdirs;
    const char *dsp = Sdefaultheapdirs;

    path = pathbuf;
    while (1) {
      if (!next_path(pathbuf, name, ext, &sp, &dsp)) {
        if (errorp) {
          fprintf(stderr, "cannot find compatible boot file %s%s in search path:\n  \"%s%s\"\n",
                  name, ext,
                  Sschemeheapdirs, Sdefaultheapdirs);
          S_abnormal_exit();
        } else {
          if (verbose) fprintf(stderr, "no compatible %s%s found\n", name, ext);
          return 0;
        }
      }

      expandedpath = S_malloc_pathname(path);
      fd = OPEN(expandedpath, O_BINARY|O_RDONLY, 0);
      free(expandedpath);
      if (fd == -1) {
        if (verbose) fprintf(stderr, "trying %s...cannot open\n", path);
        continue;
      }

      if (verbose) fprintf(stderr, "trying %s...opened\n", path);

      if (check_boot(fd, verbose, path))
        break;
    }
  }

  if (verbose) fprintf(stderr, "version and machine type check\n");

  check_dependencies_header(fd, path);

  /* ( */
  if ((c = get_u8(fd)) == ')') {
    if (boot_count != 0) {
      fprintf(stderr, "base boot file %s must come before other boot files\n", path);
      CLOSE(fd);
      S_abnormal_exit();
    }
  } else {
    if (boot_count == 0) {
      for (;;) {
       /* try to load heap or boot file this boot file requires */
        if (get_string(fd, buf, PATH_MAX, &c) != 0) {
          fprintf(stderr, "unexpected end of file on %s\n", path);
          CLOSE(fd);
          S_abnormal_exit();
        }
        if (find_boot(buf, ".boot", 0, -1, 0)) break;
        if (c == ')') {
          char *sep; char *wastebuf[8];
          fprintf(stderr, "cannot find subordinate boot file");
          if (LSEEK(fd, 0, SEEK_SET) != 0 || READ(fd, wastebuf, 8) != 8) { /* attempt to rewind and read magic number */
            fprintf(stderr, "---retry with verbose flag for more information\n");
            CLOSE(fd);
            S_abnormal_exit();
          }
          (void) get_uptr(fd, &n); /* version */
          (void) get_uptr(fd, &n); /* machine type */
          (void) get_u8(fd);        /* open paren */
          c = get_u8(fd);
          for (sep = " "; ; sep = "or ") {
            if (c == ')') break;
            (void) get_string(fd, buf, PATH_MAX, &c);
            fprintf(stderr, "%s%s.boot ", sep, buf);
          }
          fprintf(stderr, "required by %s\n", path);
          CLOSE(fd);
          S_abnormal_exit();
        }
      }
    }

   /* skip to end of header */
    finish_dependencies_header(fd, path, c);
  }

  if (boot_count >= MAX_BOOT_FILES) {
    fprintf(stderr, "exceeded maximum number of boot files (%d)\n", MAX_BOOT_FILES);
    S_abnormal_exit();
  }

  bd[boot_count].fd = fd;
  bd[boot_count].offset = 0;
  bd[boot_count].len = 0;
  bd[boot_count].contents = 0;
  bd[boot_count].need_check = 0;
  bd[boot_count].close_after = 1;
  strncpy(bd[boot_count].path, path, PATH_MAX);
  boot_count += 1;

  return 1;
}

static octet get_u8(INT fd) {
  octet buf[1];
  if (READ(fd, &buf, 1) != 1) return -1;
  return buf[0];
}

static uptr get_uptr(INT fd, uptr *pn) {
  uptr n, m; int c; octet k;

  if ((c = get_u8(fd)) < 0) return -1;
  k = (octet)c;
  n = k & 0x7F;
  while (k & 128) {
    if ((c = get_u8(fd)) < 0) return -1;
    k = (octet)c;
    m = n << 7;
    if (m >> 7 != n) return -1;
    n = m | (k  & 0x7F);
  }
  *pn = n;
  return 0;
}

static INT get_string(fd, s, max, c) INT fd; char *s; iptr max; INT *c; {
  while (max-- > 0) {
    if (*c < 0) return -1;
    if (*c == ' ' || *c == ')') {
      if (*c == ' ') *c = get_u8(fd);
      *s = 0;
      return 0;
    }
    *s++ = *c;
    *c = get_u8(fd);
  }
  return -1;
}

static IBOOL loadecho = 0;
#define LOADSKIP 0

static int set_load_binary(iptr n) {
  if (!Ssymbolp(SYMVAL(S_G.scheme_version_id))) return 0; // set by back.ss
  ptr make_load_binary = SYMVAL(S_G.make_load_binary_id);
  if (Sprocedurep(make_load_binary)) {
    S_G.load_binary = Scall1(make_load_binary, Sstring_utf8(bd[n].path, -1));
    return 1;
  }
  return 0;
}

static void boot_element(ptr tc, ptr x, iptr n) {
  if (Sprocedurep(x)) {
    S_initframe(tc, 0);
    x = boot_call(tc, x, 0);
  } else if (Sprocedurep(S_G.load_binary) || set_load_binary(n)) {
    S_initframe(tc, 1);
    S_put_arg(tc, 1, x);
    x = boot_call(tc, S_G.load_binary, 1);
  } else if (Svectorp(x)) {
    /* sequence combination by vfasl, where vectors are not nested */
    iptr i;
    for (i = 0; i < Svector_length(x); i++)
      boot_element(tc, Svector_ref(x, i), n);
  }
}

/*
 * load: boot file n in thread context tc
 * boot file n information lives in the global structure array bd[n]
 */
void load(ptr tc, iptr n, IBOOL base) {
  fprintf (stderr, "load (base %d): %ld\n", base, n);
  ptr x; iptr i;

  if (bd[n].need_check) {
    if (LSEEK(bd[n].fd, bd[n].offset, SEEK_SET) != bd[n].offset) {
      fprintf(stderr, "seek in boot file %s failed\n", bd[n].path);
      S_abnormal_exit();
    }
    check_boot(bd[n].fd, 1, bd[n].path);
    check_dependencies_header(bd[n].fd, bd[n].path);
    finish_dependencies_header(bd[n].fd, bd[n].path, 0);
  }

  if (base) {
    S_G.error_invoke_code_object = S_boot_read(bd[n].fd, bd[n].path);
    if (!Scodep(S_G.error_invoke_code_object)) {
      (void) fprintf(stderr, "first object on boot file not code object\n");
      S_abnormal_exit();
    }

    S_G.invoke_code_object = S_boot_read(bd[n].fd, bd[n].path);
    if (!Scodep(S_G.invoke_code_object)) {
      (void) fprintf(stderr, "second object on boot file not code object\n");
      S_abnormal_exit();
    }
    S_G.base_rtd = S_boot_read(bd[n].fd, bd[n].path);
    if (!Srecordp(S_G.base_rtd)) {
      S_abnormal_exit();
    }
  }

  i = 0;
  while (i++ < LOADSKIP && S_boot_read(bd[n].fd, bd[n].path) != Seof_object);

  while ((x = S_boot_read(bd[n].fd, bd[n].path)) != Seof_object) {
    if (loadecho) {
      printf("%ld: ", (long)i);
      fflush(stdout);
    }
    boot_element(tc, x, n);
    if (loadecho) {
      S_prin1(x);
      putchar('\n');
      fflush(stdout);
    }
    i += 1;
  }

  S_G.load_binary = Sfalse;
  if (bd[n].close_after)
    CLOSE(bd[n].fd);
}

extern void Sregister_boot_file(const char *name) {
  check_boot_file_state("Sregister_boot_file");
  find_boot(name, "", 0, -1, 1);
}

extern void Sregister_boot_direct_file(const char *name) {
  check_boot_file_state("Sregister_boot_direct_file");
  find_boot(name, "", 1, -1, 1);
}

extern void Sregister_boot_file_fd(const char *name, int fd) {
  check_boot_file_state("Sregister_boot_file_fd");
  find_boot(name, "", 1, fd, 1);
}

extern void Sregister_boot_file_fd_region(const char *name,
                                          int fd,
                                          iptr offset,
                                          iptr len,
                                          int close_after) {
  check_boot_file_state("Sregister_boot_file_fd");

  if (strlen(name) >= PATH_MAX) {
    fprintf(stderr, "boot-file path is too long %s\n", name);
    S_abnormal_exit();
  }

  bd[boot_count].fd = fd;
  bd[boot_count].offset = offset;
  bd[boot_count].len = len;
  bd[boot_count].contents = NULL;
  bd[boot_count].need_check = 1;
  bd[boot_count].close_after = close_after;
  strncpy(bd[boot_count].path, name, PATH_MAX);
  boot_count += 1;

  /* Read the boot file into memory if we have a len for it */
  if (len > 0) {
    char *contents = malloc(len * sizeof(*contents));
    if (!contents) // leave unbuffered if not enough memory
      return;

    ssize_t left = len;
    while (left > 0) {
      const ssize_t bytes_read = read(fd, contents, len);
      if (bytes_read == -1) { // error
        fprintf(stderr, "unable to read boot file %s\n", name);
        S_abnormal_exit();
      }
      left -= bytes_read;
    }
    bd[boot_count].contents = contents;
  }
}

static void check_boot_file_state(const char *who) {
  switch (current_state) {
    case UNINITIALIZED:
    case DEINITIALIZED:
      fprintf(stderr, "error (%s): uninitialized; call Sscheme_init first\n", who);
      if (current_state == UNINITIALIZED) exit(1); else S_abnormal_exit();
    case RUNNING:
      fprintf(stderr, "error (%s): already running\n", who);
      S_abnormal_exit();
    case BOOTING:
      break;
  }
}

/* next_path isolates the next entry in the two-part search path sp/dsp,
 * leaving the full path with name affixed in path and *sp / *dsp pointing
 * past the current entry.  it returns 1 on success and 0 if at the end of
 * the search path.  path should be a pointer to an unoccupied buffer
 * PATH_MAX characters long.  either or both of sp/dsp may be empty,
 * but neither may be null, i.e., (char *)0. */
static IBOOL next_path(path, name, ext, sp, dsp) char *path; const char *name, *ext, **sp, **dsp; {
  char *p;
  const char *s, *t;

#define setp(c) if (p >= path + PATH_MAX) { fprintf(stderr, "search path entry too long\n"); S_abnormal_exit(); } else *p++ = (c)
  for (;;) {
    s = *sp;
    p = path;
  /* copy first searchpath entry into path, substituting MACHINE_TYPE for %m,
   * VERSION for %v, % for %%, and : (; windows) for %: (%; windows) */
    while (*s != 0 && *s != SEARCHPATHSEP) {
      switch (*s) {
        case '%':
          s += 1;
          switch (*s) {
#ifdef WIN32
            case 'x': {
              wchar_t exepath[PATH_MAX]; DWORD n;
              s += 1;
              n = GetModuleFileNameW(NULL, exepath, PATH_MAX);
              if (n == 0 || (n == PATH_MAX && GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
                fprintf(stderr, "warning: executable path is too long; ignoring %%x\n");
              } else {
                char *tstart;
                const char *tend;
                tstart = Swide_to_utf8(exepath);
                t = tstart;
                tend = path_last(t);
                if (tend != t) tend -= 1; /* back up to directory separator */
                while (t != tend) setp(*t++);
                free(tstart);
              }
              break;
            }
#endif
            case 'm':
              s += 1;
              t = MACHINE_TYPE;
              while (*t != 0) setp(*t++);
              break;
            case 'v':
              s += 1;
              t = VERSION;
              while (*t != 0) setp(*t++);
              break;
            case '%':
            case SEARCHPATHSEP:
              setp(*s++);
              break;
            default:
              fprintf(stderr, "warning: ignoring extra %% in search path\n");
              break;
          }
          break;
        default:
          setp(*s++);
          break;
      }
    }

  /* unless entry was null, append name and ext onto path and return true with
   * updated path, sp, and possibly dsp */
    if (s != *sp) {
      if ((p > path) && !DIRMARKERP(*(p - 1))) { setp(PATHSEP); }
      t = name;
      while (*t != 0) setp(*t++);
      t = ext;
      while (*t != 0) setp(*t++);
      setp(0);
      *sp = s;
      return 1;
    }

  /* if current segment is empty, move to next segment.  if next segment
   * is empty, return false */
    if (*s == 0) {
      if (*(*sp = *dsp) == 0) return 0;
      *dsp = "";
    } else {
      *sp = s + 1;
    }
  }
#undef setp
}
