# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: broker_fuzz_test_config
- **Vulnerability Type**: Heap-buffer-overflow (write)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Operation**: WRITE of size 224 bytes
- **Crash Location**: src/conf.c:166
- **Vulnerable Function**: config__add_listener
- **DEDUP Token**: `__asan_memset--config__add_listener--config__create_default_listener`
- **Scariness Score**: 45 (multi-byte-write-heap-buffer-overflow)

### Stack Trace
```
#0 __asan_memset (ASan instrumentation)
#1 config__add_listener /src/cp-c-mosquitto-src/src/conf.c:166:2
#2 config__create_default_listener /src/cp-c-mosquitto-src/src/conf.c:185:5
#3 config__read_file_core /src/cp-c-mosquitto-src/src/conf.c:2171:6
#4 config__read_file /src/cp-c-mosquitto-src/src/conf.c:2535:7
#5 config__read /src/cp-c-mosquitto-src/src/conf.c
#6 config__parse_args /src/cp-c-mosquitto-src/src/conf.c:524:8
#7 mosquitto_fuzz_main /src/cp-c-mosquitto-src/src/mosquitto.c:433:7
```

### Memory Details
- **Address**: 0x511000000398 (0 bytes after a 216-byte heap region)
- **Allocated region**: [0x5110000002c0, 0x511000000398)
- **Allocation**: Via `malloc` -> `CRYPTO_zalloc` (OpenSSL library)
- **Problem**: Writing 224 bytes (`sizeof(struct mosquitto__listener)`) beyond allocated region

## Vulnerable Code Location(s)

### Location 1: crash_site
- **Type**: crash_site
- **File Path**: src/conf.c
- **Function**: config__add_listener
- **Line Range**: 166-166
- **Column Range**: 2-2

### Location 2: root_cause
- **Type**: root_cause
- **File Path**: src/conf.c
- **Function**: config__add_listener
- **Line Range**: 165-165
- **Column Range**: 1-1

### Code Context

**Vulnerable code (before patch):**
```c
static int config__add_listener(struct mosquitto__config *config)
{
	struct mosquitto__listener *listener;
	int def_listener = -1;

	if(config->default_listener){
		for(int i=0; i<config->listener_count; i++){
			if(&config->listeners[i] == config->default_listener){
				def_listener = i;
				break;
			}
		}
	}
	config->listeners = mosquitto_realloc(config->listeners, 
	                    sizeof(struct mosquitto__listener)*(size_t)(config->listener_count+1));
	if(!config->listeners){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	listener = &config->listeners[config->listener_count-1];  // BUG: Off-by-one error
	memset(listener, 0, sizeof(struct mosquitto__listener));  // CRASH: Write out of bounds
	// ...
}
```

**The bug**: Line 165 calculates the listener pointer as `&config->listeners[config->listener_count-1]`. However, after reallocation on line 160, the array has `config->listener_count+1` elements (indices 0 to `config->listener_count`). The new element should be at index `config->listener_count`, not `config->listener_count-1`.

**Fixed code (after patch):**
```c
static int config__add_listener(struct mosquitto__config *config)
{
	struct mosquitto__listener *listener;
	struct mosquitto__listener **new_listeners;
	int def_listener = -1;

	if(config->default_listener){
		for(int i=0; i<config->listener_count; i++){
			if(&config->listeners[i] == config->default_listener){
				def_listener = i;
				break;
			}
		}
	}
	new_listeners = mosquitto_realloc(config->listeners, 
	                sizeof(struct mosquitto__listener)*(size_t)(config->listener_count+1));
	if(!new_listeners){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
	config->listeners = new_listeners;
	listener = &config->listeners[config->listener_count];  // FIXED: Correct index
	memset(listener, 0, sizeof(struct mosquitto__listener));
	// ...
}
```

## CWE Classification
- **CWE-787**: Out-of-bounds Write
- **CWE-122**: Heap-based Buffer Overflow

## Vulnerability Description

This is a **heap-based buffer overflow** vulnerability caused by an **off-by-one indexing error** in the `config__add_listener` function.

### Root Cause
When adding a new listener to the configuration, the code:
1. Reallocates the `config->listeners` array to size `config->listener_count+1`
2. Incorrectly calculates the pointer to the new listener as `&config->listeners[config->listener_count-1]`
3. This points to the **last existing element** instead of the newly allocated slot

### Attack Vector
The vulnerability is triggered when:
1. A configuration option requiring a default listener is processed (e.g., `psk_hint`)
2. The `config__create_default_listener` function calls `config__add_listener`
3. The off-by-one error causes `memset` to write 224 bytes (size of `struct mosquitto__listener`) to the wrong location
4. This overwrites heap metadata and potentially adjacent heap objects

### Impact
- **Memory corruption**: Overwrites heap memory beyond the allocated buffer
- **Denial of Service**: Crashes the Mosquitto broker during configuration parsing
- **Potential code execution**: Heap overflow could potentially be exploited for arbitrary code execution depending on what data is overwritten

### Triggering Condition
The crash log shows the vulnerability is triggered when processing a configuration with the `psk_hint` option but no explicit listener defined, causing the creation of a default listener.

## POV Analysis

**POV file**: `benchmarks/atlanta-mosquitto-delta-01/.aixcc/broker_fuzz_test_config/cpv_0/blobs/pov_0.blob`

The POV is a 67-byte configuration file that triggers the vulnerability by:
1. Containing a configuration option (likely `psk_hint`) that requires a listener
2. Not defining an explicit listener, forcing `config__create_default_listener` to be called
3. This causes the vulnerable `config__add_listener` path to execute with the off-by-one error

## Patch Analysis

The patch makes two key changes:

1. **Safe realloc pattern**: Uses a temporary pointer `new_listeners` for the realloc result, only updating `config->listeners` after successful reallocation. This prevents losing the original pointer if realloc fails.

2. **Index fix**: Changes line 165 from:
   ```c
   listener = &config->listeners[config->listener_count-1];
   ```
   to:
   ```c
   listener = &config->listeners[config->listener_count];
   ```
   This correctly points to the newly allocated element at index `config->listener_count`.

The fix addresses both the off-by-one error (root cause) and improves error handling for realloc failures.

## Recommendations

### For vuln.yaml Generation:
- **Suggested CWEs**: [CWE-787, CWE-122]
- **Vulnerability name**: "Off-by-one heap buffer overflow in config__add_listener"
- **Locations**:
  - **crash_site**: src/conf.c:166 (memset call)
  - **root_cause**: src/conf.c:165 (incorrect index calculation)
- **Origin**: synthetic
- **Release date**: 02/01/2026

### Verification Notes:
- The commit hash `806fb8aaceecebe5497192db21a194bf2bec4666` does not exist in the public Eclipse Mosquitto repository
- Web searches found no CVE, OSV, GHSA, or official bug report matching this specific vulnerability
- This confirms the vulnerability is synthetic (created for benchmarking purposes)