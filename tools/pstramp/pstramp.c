/*
 * pstramp — process spawn trampoline
 *
 * Lightweight helper for process isolation. Performs optional session and
 * controlling-terminal setup, then exec()s into the requested command.
 *
 * Usage:
 *   pstramp [-setctty] [-disclaim] -- command [args...]
 *
 * Flags:
 *   -setctty   Create a new session (setsid) and claim stdin as the
 *              controlling terminal (TIOCSCTTY).
 *   -disclaim  Use posix_spawn with POSIX_SPAWN_DISCLAIM to relinquish
 *              the parent's responsibility claims (macOS only).
 */

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TIOCSCTTY
#define TIOCSCTTY 0x20007461
#endif

/* macOS 13+ exposes POSIX_SPAWN_DISCLAIM via <spawn.h>. Older SDKs may
   not define it, so provide a fallback. */
#ifndef POSIX_SPAWN_DISCLAIM
#define POSIX_SPAWN_DISCLAIM 0x2000
#endif

extern char **environ;

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s [-setctty] [-disclaim] -- command [args...]\n",
            argv0);
    exit(1);
}

int main(int argc, char *argv[]) {
    int do_setctty = 0;
    int do_disclaim = 0;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        } else if (strcmp(argv[i], "-setctty") == 0) {
            do_setctty = 1;
        } else if (strcmp(argv[i], "-disclaim") == 0) {
            do_disclaim = 1;
        } else {
            fprintf(stderr, "pstramp: unknown flag: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (cmd_start < 0 || cmd_start >= argc)
        usage(argv[0]);

    /* -setctty: new session + controlling terminal. */
    if (do_setctty) {
        if (setsid() == -1) {
            perror("pstramp: setsid");
            return 1;
        }
        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) == -1) {
            perror("pstramp: ioctl TIOCSCTTY");
            return 1;
        }
    }

    /* -disclaim: use posix_spawn with POSIX_SPAWN_DISCLAIM. */
    if (do_disclaim) {
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        posix_spawnattr_setflags(&attr,
            POSIX_SPAWN_DISCLAIM | POSIX_SPAWN_SETEXEC);

        int err = posix_spawn(NULL, argv[cmd_start], NULL, &attr,
                              &argv[cmd_start], environ);
        /* posix_spawn with SETEXEC should not return on success. */
        posix_spawnattr_destroy(&attr);
        fprintf(stderr, "pstramp: posix_spawn: %s\n", strerror(err));
        return 1;
    }

    /* Default path: plain exec. */
    execvp(argv[cmd_start], &argv[cmd_start]);
    fprintf(stderr, "pstramp: exec %s: %s\n", argv[cmd_start],
            strerror(errno));
    return 1;
}
