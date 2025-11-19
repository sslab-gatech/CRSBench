#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "mock_vp.c"
#include <assert.h>
int main(int argc, char **argv)
{
    test_a();
    test_b();

    printf("success\n");
    return 0;
}

int test_a() {
    memset(g_buf, 0, sizeof(g_buf));
    for (int i = 0; i < 10; i++) {
        int input[2] = {0x1338, i};
        func_a(input, sizeof(input));
    }
    assert(memcmp(g_buf, "aaaaaaaaaa", 10) == 0 && "g_buf should be all 'a's");
    return 0;
}

// danger of infinite loop
int test_b() {
    memset(g_buf, 0, sizeof(g_buf));
    for (int i = 0; i < 10; i++) {
        int input[2] = {0x1338, i};
        func_b(input, sizeof(input));
    }
    assert(memcmp(g_buf, "aaaaaaaaaa", 10) == 0 && "g_buf should be all 'a's");
    return 0;
}