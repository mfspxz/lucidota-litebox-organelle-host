// Hostile test (g): fork-bomb attempt.
// Tries to fork in a tight loop (capped at 3000 attempts so the baseline
// run cannot wedge the host). With clone denied the first fork dies by
// SIGSYS; with allow_clone=true + max_processes=N, forks fail with EAGAIN
// once the RLIMIT_NPROC quota is hit.

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>

// Raw clone(2) via a RUNTIME-GENERATED syscall instruction: the static
// rewriter cannot see it, so the OUTER seccomp filter is what decides.
// Returns the child pid, or -1 with errno set.
static pid_t raw_clone(void) {
    // mov $56,%rax (clone); mov $17,%rdi (SIGCHLD); xor %rsi,%rsi;
    // xor %rdx,%rdx; xor %r10,%r10; syscall; ret
    unsigned char code[] = {
        0x48,0xc7,0xc0, 0x38,0x00,0x00,0x00, // mov $56,%rax
        0x48,0xc7,0xc7, 0x11,0x00,0x00,0x00, // mov $17,%rdi
        0x48,0x31,0xf6,                      // xor %rsi,%rsi
        0x48,0x31,0xd2,                      // xor %rdx,%rdx
        0x4d,0x31,0xd2,                      // xor %r10,%r10
        0x0f,0x05,                            // syscall
        0xc3                                  // ret
    };
    void *mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return -1;
    memcpy(mem, code, sizeof(code));
    long ret = ((long(*)())mem)();
    munmap(mem, 4096);
    if (ret < 0) { errno = (int)-ret; return -1; }
    return (pid_t)ret;
}

int main(int argc, char **argv) {
    int use_raw = argc > 1 && strcmp(argv[1], "raw") == 0;
    int ok = 0, denied = 0;
    for (int i = 0; i < 3000; i++) {
        pid_t p = use_raw ? raw_clone() : fork();
        if (p < 0) {
            denied++;
            if (errno == EAGAIN && denied >= 3) break; // quota hit, stop early
            continue;
        }
        if (p == 0) {
            _exit(0); // child exits immediately
        }
        ok++;
        // Reap to avoid zombies confounding the count.
        int st;
        while (waitpid(p, &st, WNOHANG) == 0) {}
    }
    // Reap stragglers.
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    printf("forks ok=%d denied=%d (errno=%d %s)\n", ok, denied, errno, strerror(errno));
    if (ok == 0 && denied > 0) {
        printf("OK: task creation denied/quota-hit\n");
        return 0;
    }
    if (ok >= 3000) {
        printf("UNEXPECTED: 3000 forks succeeded, no quota\n");
        return 1;
    }
    printf("PARTIAL: %d forks succeeded before denial\n", ok);
    return 0;
}
