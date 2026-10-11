// Hostile test (h): try to read inherited file descriptors.
// The parent process may hold secret files/sockets open; the sandbox child
// inherits them across clone. The guest must see exactly stdio: every other
// fd must be closed before the guest runs. This probe attempts non-blocking
// reads on fds 3..127 and reports any readable data.

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main() {
    int leaks = 0;
    for (int fd = 3; fd < 128; fd++) {
        // Non-blocking: never hang on a pipe with no data.
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0) continue; // closed
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            // Only print a prefix: never exfiltrate the actual secret bytes
            // into the evidence log beyond what's needed to prove the leak.
            printf("LEAK: fd %d readable (%zd bytes, starts with '%.32s')\n",
                   fd, n, buf);
            leaks++;
        }
    }
    if (leaks > 0) {
        printf("FAIL: %d unexpected readable fds\n", leaks);
        return 1;
    }
    printf("OK: no fds beyond stdio are readable\n");
    return 0;
}
