# Vulnerability Analysis for cpv_0

## Summary
- **CPV ID**: cpv_0
- **Harness**: fuzz
- **Vulnerability Type**: Dynamic stack buffer overflow (out-of-bounds read)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (synthetic vulnerability)

## Crash Log Analysis
- **Error Type**: AddressSanitizer: dynamic-stack-buffer-overflow
- **Crash Location**: mip/mip.c:236:70
- **Vulnerable Function**: `csumup` (called from `ipcsum` called from `rx_icmp`)
- **DEDUP Token**: `csumup--ipcsum--rx_icmp(mip_if*, pkt*)`
- **Operation**: READ of size 1 at address 0x7ffcb16d2100
- **Scariness**: 27 (1-byte-read-dynamic-stack-buffer-overflow)

### Stack Trace
```
#0 0x55c263998a7e in csumup /src/cp-c-mongoose-src/mip/mip.c:236:70
#1 0x55c263998a7e in ipcsum /src/cp-c-mongoose-src/mip/mip.c:246:18
#2 0x55c263998a7e in rx_icmp(mip_if*, pkt*) /src/cp-c-mongoose-src/mip/mip.c:457:18
#3 0x55c2639945f0 in rx_ip(mip_if*, pkt*) /src/cp-c-mongoose-src/mip/mip.c:708:5
#4 0x55c263990d4f in mip_rx(mip_if*, void*, unsigned long) /src/cp-c-mongoose-src/mip/mip.c:776:5
#5 0x55c263990406 in LLVMFuzzerTestOneInput /src/cp-c-mongoose-src/test/fuzz.c:81:5
```

## Vulnerable Code Location(s)

### Location 1 (crash_site)
- **Type**: crash_site
- **File Path**: mip/mip.c
- **Function**: csumup
- **Line Range**: 233-236
- **Column Range**: 1-1

**Code Context:**
```c
static uint32_t csumup(uint32_t sum, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *) buf;
  for (size_t i = 0; i < len; i++) sum += i & 1 ? p[i] : (uint32_t) (p[i] << 8);
  return sum;
}
```

### Location 2 (root_cause)
- **Type**: root_cause
- **File Path**: mip/mip.c
- **Function**: rx_icmp
- **Line Range**: 446-458
- **Column Range**: 1-1

**Code Context (vulnerable line 456):**
```c
static void rx_icmp(struct mip_if *ifp, struct pkt *pkt) {
  if (pkt->icmp->type == 8 && pkt->ip != NULL && pkt->ip->dst == ifp->ip) {
    struct ip *ip = tx_ip(ifp, 1, ifp->ip, pkt->ip->src,
                          sizeof(struct icmp) + pkt->pay.len);
    struct icmp *icmp = (struct icmp *) (ip + 1);
    size_t len = PDIFF(ifp->tx.buf, icmp + 1), left = ifp->tx.len - len;
    if (left > pkt->pay.len) left = pkt->pay.len;  // Don't overflow TX
    memset(icmp, 0, sizeof(*icmp));                // Set csum to 0
    memcpy(icmp + 1, pkt->pay.buf, left);          // Copy RX payload to TX
    icmp->csum = ipcsum(icmp, sizeof(*icmp) + pkt->pay.len);  // BUG: Uses pkt->pay.len instead of left
    ifp->driver->tx(ifp->tx.buf, len + left, ifp->driver_data);
  }
}
```

## CWE Classification
- **CWE-121**: Stack-based Buffer Overflow
- **CWE-125**: Out-of-bounds Read
- **CWE-787**: Out-of-bounds Write (parent category)

## Vulnerability Description

This vulnerability is a **dynamic stack buffer overflow** in the ICMP packet handling code of the Mongoose embedded networking library's MIP (Minimal IP) stack.

**Root Cause:**
The vulnerability occurs in the `rx_icmp` function at line 456 in `mip/mip.c`. When handling ICMP echo requests (ping), the code calculates a checksum over the ICMP packet. The bug is that the checksum calculation uses `pkt->pay.len` (the original received payload length) instead of `left` (the actual amount of data copied to the transmit buffer).

**Attack Vector:**
1. An attacker sends a crafted ICMP packet with a very large payload length field (e.g., 131071 bytes = 0xFFFF)
2. The `rx_icmp` function limits the actual copied data to `left` bytes (line 453) to prevent TX buffer overflow
3. However, line 456 still uses the original `pkt->pay.len` for the checksum calculation
4. The `ipcsum` function calls `csumup`, which reads beyond the allocated buffer on the stack
5. This results in a dynamic stack buffer overflow (out-of-bounds read)

**Impact:**
- Information disclosure: Reading beyond buffer boundaries may leak sensitive stack data
- Denial of service: The crash terminates the network stack
- Potential for further exploitation depending on what data is leaked

**Fix:**
The patch changes line 456 from:
```c
icmp->csum = ipcsum(icmp, sizeof(*icmp) + pkt->pay.len);
```
to:
```c
icmp->csum = ipcsum(icmp, sizeof(*icmp) + left);
```

This ensures the checksum is only calculated over the data that was actually copied.

## POV Analysis

The POV file (`pov_0.blob`) is 131,071 bytes (0xFFFF, the maximum value for a 16-bit unsigned integer), which is likely the maximum payload length that can be specified in the packet structure. The file appears to be a crafted network packet with:
- Ethernet frame header
- IP header with ICMP protocol (0x01)
- ICMP echo request (type 8)
- A very large payload filled with repeating patterns (0x8c and ASCII "0")

This crafted packet triggers the vulnerability by causing the code to read far beyond the actual data that was copied into the transmit buffer, resulting in the stack buffer overflow.

## Patch Analysis

The patch makes a critical fix to line 456 in the `rx_icmp` function. The vulnerability stems from a mismatch between:
- **What is copied**: `left` bytes (limited by TX buffer size)
- **What is checksummed**: `sizeof(*icmp) + pkt->pay.len` bytes (using the original, potentially huge payload length)

By changing the checksum calculation to use `left` instead of `pkt->pay.len`, the patch ensures that only the actual copied data is included in the checksum computation, preventing the out-of-bounds read in the `csumup` function.

The patch also includes fixes to other parts of the codebase (`mongoose.c`) for unrelated NULL pointer handling issues, but these are not part of this specific vulnerability.

## Recommendations
- **Suggested CWEs**: [CWE-121, CWE-125, CWE-787]
- **Vulnerability Name**: "ICMP Checksum Calculation Stack Buffer Overflow"
- **Severity**: Medium to High (information disclosure, denial of service)
- **Affected Component**: MIP stack ICMP handler in Mongoose networking library
- **Origin Classification**: Synthetic (created for benchmarking, not a real-world CVE)