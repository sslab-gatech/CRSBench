#!/bin/bash
set -e

# This project has no pre-existing unit tests
# We create basic functionality tests for each module

cd /src/missing-vulnerabilities

# Recompile source files for testing (without fuzzer instrumentation)
echo "=== Compiling source files for testing ==="
$CC $CFLAGS -c audio.c -o audio_test.o
$CC $CFLAGS -c message.c -o message_test.o
$CC $CFLAGS -c user.c -o user_test.o
$CXX $CXXFLAGS -c auth.cpp -o auth_test.o

echo "=== Testing audio.c module ==="
# Test 1: Valid audio processing with magic value
cat > test_audio.c << 'EOF'
#include "audio.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main() {
    // Test 1: Valid input with magic value
    uint8_t valid_data[] = {
        0xef, 0xbe, 0xad, 0xde,  // Magic: 0xdeadbeef (little-endian)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    int16_t* result = process_audio_data(valid_data, sizeof(valid_data));
    assert(result != NULL && "Valid audio data should return non-NULL");

    // Test 2: Invalid magic value should return NULL
    uint8_t invalid_magic[] = {
        0x00, 0x00, 0x00, 0x00,  // Wrong magic
        0x01, 0x02, 0x03, 0x04
    };
    result = process_audio_data(invalid_magic, sizeof(invalid_magic));
    assert(result == NULL && "Invalid magic should return NULL");

    // Test 3: Too small input should return NULL
    uint8_t small_data[] = {0x01, 0x02};
    result = process_audio_data(small_data, sizeof(small_data));
    assert(result == NULL && "Small data should return NULL");

    printf("audio.c tests PASSED\n");
    return 0;
}
EOF

$CC $CFLAGS -I. test_audio.c audio_test.o -o test_audio
./test_audio

echo "=== Testing message.c module ==="
# Test 2: Message parsing
cat > test_message.c << 'EOF'
#include "message.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main() {
    // Test 1: Valid message with correct header
    uint8_t valid_msg[] = {
        0x42, 0x47, 0x53, 0x4D,  // Header: "MSGB" = 0x4D534742
        0x08, 0x00, 0x00, 0x00,  // Payload length: 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  // Payload
    };
    uint8_t* result = parse_message(valid_msg, sizeof(valid_msg));
    // Note: parse_message returns a pointer to stack memory (bug), but test should work
    assert(result != NULL && "Valid message should return non-NULL");

    // Test 2: Invalid header should return NULL
    uint8_t invalid_header[] = {
        0x00, 0x00, 0x00, 0x00,  // Wrong header
        0x04, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04
    };
    result = parse_message(invalid_header, sizeof(invalid_header));
    assert(result == NULL && "Invalid header should return NULL");

    // Test 3: Too small input should return NULL
    uint8_t small_msg[] = {0x01, 0x02};
    result = parse_message(small_msg, sizeof(small_msg));
    assert(result == NULL && "Small message should return NULL");

    printf("message.c tests PASSED\n");
    return 0;
}
EOF

$CC $CFLAGS -I. test_message.c message_test.o -o test_message
./test_message

echo "=== Testing auth.cpp/user.c module ==="
# Test 3: User authentication
cat > test_auth.cpp << 'EOF'
#include "auth.h"
#include "user.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

int main() {
    // Test 1: Valid authentication with correct key
    uint8_t valid_auth[] = {
        0xee, 0xff, 0xc0, 0x00,  // Key: 0xc0ffee (little-endian)
        0x08, 0x00, 0x00, 0x00,  // Username length: 8
        'u', 's', 'e', 'r', 'n', 'a', 'm', 'e'
    };
    // This should not crash
    authenticate_user(valid_auth, sizeof(valid_auth));

    // Test 2: Invalid key should be handled
    uint8_t invalid_key[] = {
        0x00, 0x00, 0x00, 0x00,  // Wrong key
        0x04, 0x00, 0x00, 0x00,
        'u', 's', 'e', 'r'
    };
    authenticate_user(invalid_key, sizeof(invalid_key));

    // Test 3: Too small input should be handled
    uint8_t small_auth[] = {0x01, 0x02};
    authenticate_user(small_auth, sizeof(small_auth));

    printf("auth.cpp/user.c tests PASSED\n");
    return 0;
}
EOF

$CXX $CXXFLAGS -I. test_auth.cpp auth_test.o user_test.o -o test_auth -pthread
./test_auth

echo "=== All tests PASSED ==="
exit 0
