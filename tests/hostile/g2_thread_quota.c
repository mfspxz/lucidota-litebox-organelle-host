// Quota probe: spawn pthreads in a loop. With allow_clone=true and
// max_processes=N, pthread_create must start failing (EAGAIN) once the
// RLIMIT_NPROC quota is hit. (Default-deny manifests never reach here:
// the outer filter kills the first clone with SIGSYS.)

#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static void *spin(void *a) { (void)a; sleep(30); return NULL; }

int main() {
    int ok = 0, denied = 0, first_err = 0;
    pthread_t th[512];
    for (int i = 0; i < 512; i++) {
        int rc = pthread_create(&th[i], NULL, spin, NULL);
        if (rc != 0) {
            if (denied == 0) first_err = rc;
            denied++;
            if (rc == EAGAIN && denied >= 3) break;
            continue;
        }
        ok++;
    }
    printf("threads ok=%d denied=%d first_errno=%d (%s)\n", ok, denied, first_err, strerror(first_err));
    if (denied > 0 && ok < 512) {
        printf("OK: thread creation quota-hit at %d\n", ok);
        return 0;
    }
    printf("UNEXPECTED: 512 threads, no quota\n");
    return 1;
}
