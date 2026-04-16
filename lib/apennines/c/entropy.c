#include "apennines/entropy.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

unsigned long entropy_get_system(u8 *out, u64 len) {
    if (!out) return 1;
    if (len == 0) return 0;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        NULL,
        (PUCHAR)out,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status != 0) return 2;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 2;

    u64 total = 0;
    while (total < len) {
        ssize_t n = read(fd, out + total, (size_t)(len - total));
        if (n <= 0) {
            close(fd);
            return 2;
        }
        total += (u64)n;
    }
    close(fd);
#endif

    return 0;
}
