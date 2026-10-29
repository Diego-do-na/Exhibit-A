/*
 * fanotify_observer.c -- SPIKE, not product code.
 *
 * Candidate 3 of the A-1 spike: a host-side watch on the canary FILE. The
 * orchestrator (outside any container) watches the real host file that is
 * bind-mounted into the test container as the canary. fanotify reports an open
 * of that inode no matter how it happened -- Python open, a `cat` subprocess,
 * an mmap, a C extension -- because it hooks the VFS, not the language runtime.
 *
 * What it proves and does not: it proves SOMEONE opened the canary, and gives
 * the opener's pid (in the watcher's pid namespace) and, with a permission
 * event, can even block the open. It recovers NO application provenance: it
 * cannot see the Python call stack, and the pid belongs to a process in a
 * different (container) pid namespace, so mapping it back to "application code
 * through an entry point" is not possible from here. Its value is as a cheap,
 * completely out-of-reach SECOND SIGNAL: a read the in-process hook missed, or
 * that a cheat suppressed, still trips this.
 *
 * Needs CAP_SYS_ADMIN (fanotify). Runs on the HOST / orchestrator, never in the
 * sandbox. Linux only; fanotify FAN_OPEN marking of a single file is portable
 * across x86_64 and aarch64 (it is arch-independent, unlike the ptrace variant).
 *
 * Build: gcc -O2 -Wall -o fanotify_observer fanotify_observer.c
 * Usage: fanotify_observer <canary-file> <events-out|->   (runs until SIGINT)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/fanotify.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <canary-file> <events-out|->\n", argv[0]);
        return 2;
    }
    FILE *out = strcmp(argv[2], "-") == 0 ? stdout : fopen(argv[2], "w");
    if (!out) { perror("open(events-out)"); return 2; }

    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (fan < 0) { perror("fanotify_init (needs CAP_SYS_ADMIN)"); return 1; }

    /* Watch opens of just this one file (the canary inode). */
    if (fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, argv[1]) < 0) {
        perror("fanotify_mark");
        return 1;
    }
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    fprintf(stderr, "[fanotify_observer] watching %s\n", argv[1]);

    char buf[4096];
    while (!g_stop) {
        ssize_t len = read(fan, buf, sizeof(buf));
        if (len < 0) { if (errno == EINTR) break; perror("read"); break; }
        for (char *p = buf; p < buf + len;) {
            struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)p;
            if (m->vers != FANOTIFY_METADATA_VERSION) break;
            if (m->mask & FAN_OPEN) {
                fprintf(out,
                    "{\"observer\":\"fanotify\",\"event\":\"open\",\"host_pid\":%d}\n",
                    (int)m->pid);
                fflush(out);
                fprintf(stderr, "[fanotify_observer] canary opened by host_pid=%d\n",
                        (int)m->pid);
            }
            if (m->fd >= 0) close(m->fd);
            p += m->event_len;
        }
    }
    if (out != stdout) fclose(out);
    return 0;
}
