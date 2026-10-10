// Hostile test (f): emit output continuously until killed.
// The parent must NOT accumulate this unboundedly: the bounded drain caps
// retained bytes, hashes incrementally, and marks truncation in the receipt.
// (Stack buffer + fwrite: heap-malloc + setvbuf(_IONBF) variants SIGSEGV
//  inside the LiteBox shim before emitting anything — an unrelated shim
//  quirk, not the output path under test.)

#include <stdio.h>
#include <string.h>

int main() {
    char line[4096];
    memset(line, 'X', sizeof(line) - 1);
    line[sizeof(line) - 1] = '\n';
    for (;;) {
        if (fwrite(line, 1, sizeof(line), stdout) != sizeof(line)) {
            return 0; // pipe closed / error: stop
        }
    }
    return 0;
}
