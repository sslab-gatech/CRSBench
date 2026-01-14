# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: fuzzshark_ip
- **Vulnerability Type**: Global buffer overflow (type mismatch leading to out-of-bounds read)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (no CVE or public vulnerability reference found)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: global-buffer-overflow
- **Crash Location**: epan/dissectors/packet-osi-options.c:519:16
- **Vulnerable Function**: dissect_osi_options
- **DEDUP Token**: dissect_osi_options--esis_dissect_esh_pdu--dissect_esis
- **Read Size**: 4 bytes at address 0x0000107b1400
- **SCARINESS**: 17 (4-byte-read-global-buffer-overflow)

### Stack Trace
The crash occurs when processing OSI options in the ESIS (End System To Intermediate System) dissector:

```
#0 dissect_osi_options /src/cp-c-wireshark/epan/dissectors/packet-osi-options.c:519:16
#1 esis_dissect_esh_pdu /src/cp-c-wireshark/epan/dissectors/packet-esis.c:149:5
#2 dissect_esis /src/cp-c-wireshark/epan/dissectors/packet-esis.c:300:5
#3 call_dissector_through_handle /src/cp-c-wireshark/epan/packet.c:858:9
```

### Memory Analysis
From the crash log, the overflow occurs at:
- Address `0x0000107b1400` is located 0 bytes after the global variable `clnp_decode_atn_options` (size 1 byte)
- The READ attempts to access 4 bytes from this 1-byte boolean variable
- This is 32 bytes before the `hf_clnp_id` global variable

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: epan/dissectors/packet-osi-options.c
- **Function**: dissect_osi_options
- **Line Range**: 519-519
- **Column Range**: 16-16

### Location 2 (root_cause)
- **Type**: root_cause  
- **File Path**: epan/dissectors/packet-osi-options.c
- **Function**: (extern declaration at file top)
- **Line Range**: 108-108
- **Column Range**: 1-50

### Code Context

**Crash site (packet-osi-options.c:519):**
```c
case OSI_OPT_SECURITY:
  octet = tvb_get_guint8(tvb, offset);
  if ( clnp_decode_atn_options ) {  // <- LINE 519: Crash occurs here
    dissect_option_atn_security_label(octet,parm_len,tvb, offset,
                                      osi_option_tree);
  } else {
    ti = proto_tree_add_item(osi_option_tree, hf_osi_options_security_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_set_len(ti, parm_len);
  }
  break;
```

**Root cause (packet-osi-options.c:108):**
```c
extern gboolean clnp_decode_atn_options; /* as defined in packet-clnp.c */
```

**Actual definition (packet-clnp.c:188):**
```c
bool clnp_decode_atn_options = false;
```

## Root Cause Analysis

This is a **type mismatch vulnerability** caused by an inconsistent type declaration:

1. **Declaration mismatch**: In `packet-osi-options.c`, the variable is declared as `extern gboolean` (4 bytes on most platforms)
2. **Actual definition**: In `packet-clnp.c`, the variable is defined as `bool` (1 byte in C99)
3. **Buffer overflow**: When `packet-osi-options.c` reads the variable at line 519, it attempts to read 4 bytes (`gboolean` size) from a 1-byte `bool` variable
4. **Out-of-bounds read**: This causes a 4-byte read from a 1-byte global variable, resulting in a 3-byte buffer overflow into adjacent memory

The mismatch between the extern declaration type (`gboolean`) and the actual definition type (`bool`) causes the compiler to generate code that reads beyond the actual variable's allocated size.

## CWE Classification
- **CWE-843**: Access of Resource Using Incompatible Type ('Type Confusion')
- **CWE-125**: Out-of-bounds Read
- **CWE-787**: Out-of-bounds Write (secondary, as incorrect reads could lead to incorrect writes elsewhere)

## Vulnerability Description

A global buffer overflow vulnerability exists in Wireshark's OSI options dissector due to a type mismatch between an extern declaration and its actual definition. The `clnp_decode_atn_options` variable is declared as `gboolean` (typically 4 bytes) in `packet-osi-options.c` but defined as `bool` (1 byte) in `packet-clnp.c`. When the dissector evaluates this variable at line 519 during OSI security option processing, it attempts to read 4 bytes from a 1-byte variable, causing a 3-byte out-of-bounds read that accesses adjacent global memory.

This vulnerability can be triggered when processing specially crafted OSI/ESIS packets with security options (type 0xc5), leading to potential information disclosure through memory leakage or application crashes. The overflow affects the ESIS (End System To Intermediate System) protocol dissector when handling ATN (Aeronautical Telecommunication Network) security label options.

**Impact:**
- Information disclosure (reading 3 bytes beyond the variable)
- Denial of Service (application crash)
- Potential for exploitation if adjacent memory contains sensitive data

## POV Analysis

The POV file (`pov_0.blob`, 73 bytes) contains a specially crafted network packet that triggers the OSI security option parsing path. The packet structure includes:
- Ethernet frame with LLC (Logical Link Control) encapsulation
- OSI/ESIS protocol data
- A security option (type 0xc5) that triggers the vulnerable code path at line 519

The packet forces execution through the dissector chain:
```
dissect_frame → dissect_ipv6 → dissect_etherip → dissect_eth_withoutfcs → 
dissect_llc → dissect_osi → dissect_esis → esis_dissect_esh_pdu → dissect_osi_options
```

## Patch Analysis

The patch fixes the vulnerability by correcting the type mismatch:

**File: epan/dissectors/packet-osi-options.c (line 108)**
```diff
-extern gboolean clnp_decode_atn_options; /* as defined in packet-clnp.c */
+extern bool clnp_decode_atn_options; /* as defined in packet-clnp.c */
```

The fix changes the extern declaration from `gboolean` (4 bytes) to `bool` (1 byte), matching the actual definition in `packet-clnp.c:188`. This ensures the variable is accessed with the correct size, preventing the out-of-bounds read.

**Additional changes**: The patch also removes unused extern declarations in `packet-ansi_tcap.c` (lines related to `gtcap_PersistentSRT`, `gtcap_RepetitionTimeout`, and `gtcap_LostTimeout`), which are cleanup changes unrelated to the vulnerability.

## Recommendations
- **Suggested CWEs**: [CWE-843, CWE-125, CWE-787]
- **Vulnerability Name**: OSI Options Dissector Type Mismatch Global Buffer Overflow
- **Severity**: Medium to High (information disclosure and DoS potential)
- **Fix**: Align the extern declaration type with the actual variable definition type