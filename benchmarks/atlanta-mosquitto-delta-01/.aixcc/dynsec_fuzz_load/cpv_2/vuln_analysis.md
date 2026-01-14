# Vulnerability Analysis for cpv_2

## Summary
- **CPV ID**: cpv_2
- **Harness**: dynsec_fuzz_load
- **Vulnerability Type**: Heap-use-after-free
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: N/A (no CVE assigned)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-use-after-free
- **Crash Location**: plugins/dynamic-security/clients.c:67
- **Vulnerable Function**: dynsec_clients__find
- **DEDUP Token**: dynsec_clients__find--client__free_item--dynsec_clients__cleanup

### Stack Trace
```
==14==ERROR: AddressSanitizer: heap-use-after-free on address 0x50c000000100 at pc 0x55bee4e5ecc0 bp 0x7ffd8f69a020 sp 0x7ffd8f69a018
READ of size 8 at 0x50c000000100 thread T0
SCARINESS: 51 (8-byte-read-heap-use-after-free)
    #0 0x55bee4e5ecbf in dynsec_clients__find /src/cp-c-mosquitto-src/plugins/dynamic-security/clients.c:67:3
    #1 0x55bee4e5ee19 in client__free_item /src/cp-c-mosquitto-src/plugins/dynamic-security/clients.c:78:17
    #2 0x55bee4e5ed5d in dynsec_clients__cleanup /src/cp-c-mosquitto-src/plugins/dynamic-security/clients.c:96:3
    #3 0x55bee4e45c83 in mosquitto_plugin_cleanup /src/cp-c-mosquitto-src/plugins/dynamic-security/plugin.c:143:2
```

The crash shows that memory at 0x50c000000100 was:
- **Freed by**: `mosquitto_free` called from `dynsec_clients__cleanup` at line 96
- **Allocated by**: `mosquitto_calloc` called from `dynsec_clients__config_load` at line 133
- **Accessed after free**: By `dynsec_clients__find` via `HASH_FIND` macro at line 67

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: plugins/dynamic-security/clients.c
- **Function**: dynsec_clients__find
- **Line Range**: 67-67
- **Column Range**: 3-3

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: plugins/dynamic-security/clients.c
- **Function**: dynsec_clients__config_load
- **Line Range**: 129-137
- **Column Range**: 0-0

### Code Context

**Crash site (dynsec_clients__find, line 67):**
```c
struct dynsec__client *dynsec_clients__find(struct dynsec__data *data, const char *username)
{
    struct dynsec__client *client = NULL;

    if(username){
        HASH_FIND(hh, data->clients, username, strlen(username), client);  // Line 67 - USE-AFTER-FREE
    }
    return client;
}
```

**Root cause (dynsec_clients__config_load, lines 129-137):**
```c
size_t username_len = strlen(username);
if(username_len == 0){
    continue;
}
// MISSING CHECK: Should check if client with this username already exists
// This allows duplicate clients to be added to the hash table

client = mosquitto_calloc(1, sizeof(struct dynsec__client) + username_len + 1);
if(client == NULL){
    return MOSQ_ERR_NOMEM;
}
strncpy(client->username, username, username_len);
```

## CWE Classification
- **CWE-416**: Use After Free
- **CWE-672**: Operation on a Resource after Expiration or Release

## Vulnerability Description

A heap-use-after-free vulnerability exists in the Eclipse Mosquitto dynamic security plugin's client management code. The vulnerability occurs in the `dynsec_clients__config_load` function which fails to validate whether a client with a given username already exists before adding it to the internal hash table.

**Attack Scenario:**
When a malicious JSON configuration file contains duplicate client entries with the same username (e.g., `{"clients":[{"username":"d"},{"username":"d"}]}`), the loading process creates multiple client structures with identical usernames and adds them all to the hash table using the uthash library.

**Vulnerability Trigger:**
During cleanup, when `dynsec_clients__cleanup` iterates through and frees these duplicate entries via `HASH_ITER`, the following sequence occurs:

1. First duplicate client "d" is passed to `client__free_item`
2. `client__free_item` calls `dynsec_clients__find` to locate the client in the hash table
3. The client is found, removed from hash with `HASH_DEL`, and freed with `mosquitto_free`
4. Second duplicate client "d" is passed to `client__free_item`
5. `client__free_item` calls `dynsec_clients__find` again
6. **USE-AFTER-FREE**: The `HASH_FIND` macro at line 67 attempts to access the hash table entry, but the memory was already freed in step 3, resulting in an 8-byte read from freed heap memory

**Impact:**
This vulnerability could allow an attacker who can control the dynamic security configuration file to trigger a use-after-free condition, potentially leading to:
- Information disclosure (reading freed memory)
- Denial of service (crash)
- In specific circumstances, potential code execution

## POV Analysis

The proof-of-vulnerability test case is a minimal JSON configuration that triggers the bug:

```json
{"clients":[{"username":"d"},{"username":"d"}]}
```

This POV:
- Contains two client entries with identical username "d"
- Demonstrates the vulnerability can be triggered with minimal input
- Shows the bug occurs during the config loading and cleanup cycle
- Uses a single-character username to minimize complexity

## Patch Analysis

The vulnerability was fixed in Mosquitto version 2.0.16 (released August 16, 2023) via commit b76c3c7820d9e910486d29686fc78e4c047975c3 by adding a duplicate check before allocating a new client structure:

```diff
@@ -129,6 +129,9 @@ int dynsec_clients__config_load(struct dynsec__data *data, cJSON *tree)
 			if(username_len == 0){
 				continue;
 			}
+			if(dynsec_clients__find(data, username)){
+				continue;
+			}
 
 			client = mosquitto_calloc(1, sizeof(struct dynsec__client) + username_len + 1);
 			if(client == NULL){
```

**Fix Explanation:**
The patch adds a check using `dynsec_clients__find()` to determine if a client with the given username already exists in the hash table. If a duplicate is detected, the function skips creating a new client structure and continues to the next entry. This prevents duplicate clients from being added to the hash table, eliminating the use-after-free condition during cleanup.

**Why this is synthetic:**
Despite being a real security bug fixed in a production release, this vulnerability was **not assigned a CVE** or published as a security advisory. The fix was included in the release notes as a bug fix: "Dynsec plugin will not allow duplicate clients/groups/roles when loading config from file, which matches the behaviour for when creating them." Without an official CVE, OSV, GHSA, or security advisory identifier, this must be classified as synthetic according to the analysis guidelines.

## Recommendations
- **Suggested CWEs**: [CWE-416, CWE-672]
- **Vulnerability Name**: Heap Use-After-Free in Dynamic Security Duplicate Client Processing
- **Origin**: synthetic (no CVE assigned despite being a real bug fix)
- **Release Date**: 02/01/2026 (synthetic date per guidelines)