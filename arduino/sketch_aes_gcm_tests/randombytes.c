#include <stdlib.h>
#include <stdint.h>
#include <esp_random.h>

void randombytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)esp_random();
    }
}