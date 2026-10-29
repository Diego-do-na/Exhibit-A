/*
 * ptrace_observer.c -- SPIKE, not product code.
 *
 * An out-of-process observer for candidate 1 (ptrace variant) of the A-1
 * observer spike. It runs a command as a traced child and reports every
 * open/openat/openat2 of a target "canary" path, following forks/clones/execs
 * so that reads from subprocesses are seen too.
 *
 * The point it demonstrates: the record of "the canary was opened" is produced
 * by THIS process (the tracer), by reading the syscall arguments out of the
 * tracee at the syscall-entry stop. The traced test cannot write to this
 * record, cannot stop the syscall from being observed, and cannot hide an open
 * behind a subprocess or a C extension -- it is observed at the kernel ABI, not
 * at the Python `open` audit hook.
 *
 * What it CANNOT do, and this is the finding: it sees the syscall, i.e. the
 * FACT of the read and the pid/path, but it has no idea of the Python call
 * stack, so it recovers NO application provenance on its own. x86_64 Linux only.
 *
 * Build:  gcc -O2 -Wall -o ptrace_observer ptrace_observer.c
 * Usage:  ptrace_observer <canary-abspath> <events-out> -- <cmd> [args...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <limits.h>

/* x86_64 syscall numbers. */
#define SYS_open_   2
#define SYS_openat_ 257
#define SYS_openat2_ 437

static const char *g_canary;     /* realpath of the canary */
static FILE *g_out;              /* events sink (owned by the tracer) */

/* Read a NUL-terminated string out of the tracee's address space. */
static int read_string(pid_t pid, unsigned long addr, char *buf, size_t max) {
    struct iovec local = { buf, max - 1 };
    struct iovec remote = { (void *)addr, max - 1 };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        /* Fallback: word-by-word via PTRACE_PEEKDATA (handles unmapped tails). */
        size_t i = 0;
        while (i < max - 1) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
            if (errno) return -1;
            memcpy(buf + i, &word, sizeof(word));
            for (size_t j = 0; j < sizeof(word) && i + j < max - 1; j++)
                if (buf[i + j] == '\0') { buf[max - 1] = '\0'; return 0; }
            i += sizeof(word);
        }
    }
    buf[max - 1] = '\0';
    return 0;
}

/* Does this path, resolved like the kernel would, point at the canary? */
static int is_canary(pid_t pid, const char *path) {
    char resolved[PATH_MAX];
    /* The tracee's cwd is the same as ours in this spike (same mount ns), so a
     * plain realpath from the tracer is representative. A production observer
     * would resolve relative to /proc/<pid>/cwd and /proc/<pid>/root. */
    if (realpath(path, resolved) == NULL) {
        /* openat with a relative path we can't resolve: compare the basename
         * conservatively so the demo still flags an obvious direct open. */
        const char *base = strrchr(path, '/');
        const char *cbase = strrchr(g_canary, '/');
        return base && cbase && strcmp(base, cbase) == 0;
    }
    return strcmp(resolved, g_canary) == 0;
}

static void report(pid_t pid, const char *sysname, const char *path) {
    fprintf(g_out, "{\"observer\":\"ptrace\",\"pid\":%d,\"syscall\":\"%s\",\"path\":\"%s\"}\n",
            pid, sysname, path);
    fflush(g_out);
    fprintf(stderr, "[ptrace_observer] pid=%d %s(%s) -> CANARY\n", pid, sysname, path);
}

int main(int argc, char **argv) {
    if (argc < 5 || strcmp(argv[3], "--") != 0) {
        fprintf(stderr, "usage: %s <canary> <events-out> -- <cmd> [args...]\n", argv[0]);
        return 2;
    }
    char canary_real[PATH_MAX];
    if (realpath(argv[1], canary_real) == NULL) {
        perror("realpath(canary)");
        return 2;
    }
    g_canary = canary_real;
    g_out = strcmp(argv[2], "-") == 0 ? stdout : fopen(argv[2], "w");
    if (!g_out) { perror("open(events-out)"); return 2; }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        /* Stop so the parent can set options before the first syscall. */
        raise(SIGSTOP);
        execvp(argv[4], &argv[4]);
        perror("execvp");
        _exit(127);
    }

    int status;
    int child_exit = 0;         /* exit status of the traced test command */
    int child_done = 0;
    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL,
           (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                    PTRACE_O_TRACEEXEC));
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    /* Per-pid flag: are we at syscall-entry (1) or syscall-exit (0)? */
    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == ECHILD) break;
            continue;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child) {
                /* Remember the test command's outcome; keep draining other
                 * tracees (its children) until ECHILD. The oracle needs this
                 * exit status to know red (test failed) from green. */
                child_exit = WIFEXITED(status) ? WEXITSTATUS(status)
                                               : 128 + WTERMSIG(status);
                child_done = 1;
            }
            continue;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            unsigned int event = (unsigned int)status >> 16;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_EXEC) {
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                continue;
            }
            if (sig == (SIGTRAP | 0x80)) {
                /* syscall-stop. Inspect at entry only. */
                struct user_regs_struct regs;
                /* At syscall-entry the kernel leaves rax == -ENOSYS; at exit rax
                 * holds the return value. Inspect at entry only, so each open is
                 * reported once. */
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0 &&
                    (long)regs.rax == -38) {
                    long nr = regs.orig_rax;
                    unsigned long path_arg = 0;
                    const char *name = NULL;
                    if (nr == SYS_open_)        { path_arg = regs.rdi; name = "open"; }
                    else if (nr == SYS_openat_) { path_arg = regs.rsi; name = "openat"; }
                    else if (nr == SYS_openat2_){ path_arg = regs.rsi; name = "openat2"; }
                    if (name && path_arg) {
                        char path[PATH_MAX];
                        if (read_string(pid, path_arg, path, sizeof(path)) == 0 &&
                            is_canary(pid, path))
                            report(pid, name, path);
                    }
                }
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                continue;
            }
            /* Deliver other signals transparently. */
            ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)(sig == SIGTRAP ? 0 : sig));
        }
    }
    if (g_out != stdout) fclose(g_out);
    return child_done ? child_exit : 0;
}
