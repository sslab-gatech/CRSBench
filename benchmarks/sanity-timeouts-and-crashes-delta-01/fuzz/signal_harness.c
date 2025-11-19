#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "../cp-user-timeouts-and-crashes-src/mock_vp.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    func_a(data, size);
    return 0;
}
