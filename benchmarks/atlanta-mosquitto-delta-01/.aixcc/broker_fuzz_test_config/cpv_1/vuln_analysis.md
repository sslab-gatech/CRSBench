# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: broker_fuzz_test_config
- **Vulnerability Type**: Heap-buffer-overflow (off-by-one error)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 224
- **Crash Location**: src/conf.c:166
- **Vulnerable Function**: config__add_listener
- **Calling Function**: config__create_default_listener (line 185)
- **DEDUP Token**: `__asan_memset--config__add_listener--config__create_default_listener`

### Stack Trace
```
#0 __asan_memset (ASan interceptor)
#1 config__add_listener /src/cp-c-mosquitto-src/src/conf.c:166:2
#2 config__create_default_listener /src/cp-c-mosquitto-src/src/conf.c:185:5
#3 config__read_file_core /src/cp-c-mosquitto-src/src/conf.c:2118:9
#4 config__read_file /src/cp-c-mosquitto-src/src/conf.c:2535:7
#5 config__read /src/cp-c-mosquitto-src/src/conf.c
#6 config__parse_args /src/cp-c-mosquitto-src/src/conf.c:524:8
#7 mosquitto_fuzz_main /src/cp-c-mosquitto-src/src/mosquitto.c:433:7
```

### Memory Details
- **Buffer allocated**: 216 bytes at address 0x5110000002c0
- **Write occurs at**: 0x511000000398 (0 bytes after allocated region)
- **Write size**: 224 bytes (8 bytes beyond allocated buffer)
- **Allocated via**: malloc → CRYPTO_zalloc (OpenSSL allocation)

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: src/conf.c
- **Function**: config__add_listener
- **Line Range**: 166-166
- **Column Range**: 2-8

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: src/conf.c
- **Function**: config__add_listener
- **Line Range**: 165-165
- **Column Range**: 13-49

### Code Context (Vulnerable - Before Patch)

```c
static int config__add_listener(struct mosquitto__config *config)
{
    struct mosquitto__listener *listener;
    int def_listener = -1;

    // ... default listener preservation logic ...
    
    // Line 160: Reallocate array to hold one more listener
    config->listeners = mosquitto_realloc(config->listeners, 
        sizeof(struct mosquitto__listener)*(size_t)(config->listener_count+1));
    if(!config->listeners){
        log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
        return MOSQ_ERR_NOMEM;
    }
    
    // Line 165: OFF-BY-ONE ERROR - accesses listener_count-1 instead of listener_count
    listener = &config->listeners[config->listener_count-1];  // BUG: root_cause
    
    // Line 166: memset writes to wrong location, causing heap overflow
    memset(listener, 0, sizeof(struct mosquitto__listener));  // CRASH: crash_site
    
    listener->security_options = mosquitto_calloc(1, sizeof(struct mosquitto__security_options));
    if(!listener->security_options){
        log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
        return MOSQ_ERR_NOMEM;
    }
    
    // ... restore default listener ...
    
    config->listener_count++;  // Increment happens AFTER access
    
    return MOSQ_ERR_SUCCESS;
}
```

### Code Context (Fixed - After Patch)

```c
// Line 165: Fixed to use correct index
listener = &config->listeners[config->listener_count];  // FIXED
memset(listener, 0, sizeof(struct mosquitto__listener));
```

## Root Cause Analysis

The vulnerability is an **off-by-one indexing error** in the `config__add_listener` function:

1. **Allocation**: Array is reallocated to size `listener_count + 1`
2. **Bug**: Code incorrectly accesses `listeners[listener_count - 1]` instead of `listeners[listener_count]`
3. **When listener_count = 0**: Accesses `listeners[-1]` (negative index wrapping to high memory address)
4. **When listener_count > 0**: May overwrite existing listener or write beyond allocated memory
5. **memset overflow**: Writes 224 bytes (sizeof struct mosquitto__listener) to wrong location
6. **Heap corruption**: Writes 8 bytes beyond allocated 216-byte buffer

The issue occurs because:
- Array is grown to accommodate a **new** element at index `listener_count`
- Code incorrectly uses `listener_count - 1`, which points to the **last existing** element
- `listener_count` is incremented **after** the memory operations, not before

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-787**: Out-of-bounds Write
- **CWE-193**: Off-by-one Error

## Vulnerability Description

This is a heap-based buffer overflow vulnerability caused by an off-by-one indexing error in the Mosquitto MQTT broker's configuration parser. When adding a new listener to the configuration, the code incorrectly calculates the array index for the new listener element.

The vulnerability occurs in the `config__add_listener` function at src/conf.c:165. After reallocating the listeners array to accommodate one additional listener, the code uses `config->listeners[config->listener_count-1]` to access the new listener slot. However, this is incorrect because:

1. The array has been resized to `listener_count + 1` elements
2. Valid indices are now `0` to `listener_count` (inclusive)
3. Using `listener_count - 1` accesses the **last existing** element, not the **newly allocated** slot
4. The subsequent `memset` operation writes 224 bytes to this incorrect location
5. This causes an 8-byte write beyond the allocated 216-byte heap buffer

The correct index should be `listener_count` (without the `-1`), which points to the newly allocated slot at the end of the array.

**Impact**: This vulnerability can lead to heap corruption, potential crashes, and in some scenarios could be exploited for arbitrary code execution if an attacker can control configuration file contents.

## POV Analysis

The POV file contains a minimal configuration input:
- **Content**: `"port "` (5 bytes)
- **Trigger mechanism**: The "port" option triggers deprecated code path that calls `config__create_default_listener`
- **Exploitation**: This creates a default listener when none exists (listener_count = 0), triggering the off-by-one error
- **Minimal input**: Demonstrates that very simple configuration can trigger the vulnerability

## Patch Analysis

The patch file shows a simple one-line fix in src/conf.c:

**Before (Line 165)**:
```c
listener = &config->listeners[config->listener_count-1];
```

**After (Line 165)**:
```c
listener = &config->listeners[config->listener_count];
```

**Fix explanation**:
- Removes the `-1` offset from the array index
- Correctly points to the newly allocated slot at index `listener_count`
- Prevents out-of-bounds access and heap corruption
- Simple fix that addresses the root cause directly

The patch confirms that:
- **Root cause location**: src/conf.c:165 (the incorrect array indexing)
- **Crash site location**: src/conf.c:166 (where memset writes to the wrong address)
- The fix is minimal and surgical, changing only the indexing calculation

## Recommendations

### For vuln.yaml Generation:
- **Suggested CWEs**: [CWE-122, CWE-787, CWE-193]
- **Vulnerability name**: "Heap buffer overflow due to off-by-one error in config__add_listener"
- **Origin**: synthetic (not a real-world CVE)
- **Release date**: 02/01/2026
- **Locations**:
  - crash_site: src/conf.c:166 (memset call)
  - root_cause: src/conf.c:165 (incorrect array indexing)

### Technical Details:
- **Severity**: High - heap corruption can lead to crashes or potential code execution
- **Exploitability**: Requires ability to provide malformed configuration files
- **Attack vector**: Configuration file parsing
- **Affected component**: Mosquitto broker configuration subsystem