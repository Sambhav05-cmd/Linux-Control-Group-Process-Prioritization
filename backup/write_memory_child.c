#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    size_t size = 10 * 1024 * 1024; // 10 MB
    char *mem = malloc(size);
    if (!mem) return 1;

    for (size_t i = 0; i < size; i += 4096) {
        mem[i] = 1; // Touch each page to ensure it gets mapped
    }

    while (1) {
        for (size_t i = 0; i < size; i += 4096) {
            mem[i] ^= 1; // Modify to keep it active in memory
        }
    }

    return 0;
}

