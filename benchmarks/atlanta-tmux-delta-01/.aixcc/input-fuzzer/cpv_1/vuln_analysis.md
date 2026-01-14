# Vulnerability Analysis for cpv_1

## Summary
- **CPV ID**: cpv_1
- **Harness**: input-fuzzer
- **Vulnerability Type**: heap-buffer-overflow (READ)
- **Origin**: synthetic
- **Release Date**: 02/01/2026
- **References**: None (This is a synthetic vulnerability based on a real tmux fix)

## Explanation of Origin Classification

While I found that tmux had a fix in February 2021 (commit fb42ae3071763fdc6a2fe2e57feec774623b1c33) for the `input_osc_parse_colour` function with the same issue (missing length check when skipping spaces), I could NOT find:
- Any official CVE assignment for this specific vulnerability
- Any security advisory mentioning this specific function and bug
- Any bug tracker issue describing this as a security vulnerability

The commit message "Reduce len when moving past spaces in OSC 11 parameter" suggests this was a correctness fix rather than a publicized security vulnerability. The well-known CVE-2020-27347 was for a different function (`input_csi_dispatch_sgr_colon`), not `input_osc_parse_colour`.

**Therefore, this is classified as `synthetic`** - even though it's based on real code, there's no official security reference.

## Crash Log Analysis
- **Error Type**: AddressSanitizer: heap-buffer-overflow
- **Crash Location**: input.c:2490:22
- **Vulnerable Function**: input_osc_parse_colour
- **DEDUP Token**: input_osc_parse_colour--input_osc_11--input_set_state
- **Read Size**: 1 byte
- **Scariness**: 12 (1-byte-read-heap-buffer-overflow)

### Stack Trace
```
#0 0x558b708fbf5a in input_osc_parse_colour /src/tmux/input.c:2490:22
#1 0x558b708fa48f in input_osc_11 /src/tmux/input.c:2623:11
#2 0x558b708ee192 in input_set_state /src/tmux/input.c:883:3
#3 0x558b708ee192 in input_parse /src/tmux/input.c:940:4
#4 0x558b708edc8b in input_parse_buffer /src/tmux/input.c:982:2
#5 0x558b70831b5a in LLVMFuzzerTestOneInput /src/tmux/fuzz/input-fuzzer.c:55:2
```

### Memory Information
- **Crash Address**: 0x5030000015f0
- **Access Type**: READ of size 1
- **Region**: 0 bytes after 32-byte allocated region [0x5030000015d0, 0x5030000015f0)
- **Allocation**: From `xmalloc` called in `input_init` at input.c:814

## Vulnerable Code Location(s)

### Location 1 (crash_site and root_cause are the same)
- **Type**: crash_site, root_cause
- **File Path**: input.c
- **Function**: input_osc_parse_colour
- **Line Range**: 2488-2489
- **Column Range**: 12-14 (line 2488), 4-6 (line 2489)

### Code Context
```c
} else {
    while (*p == ' ')     // Line 2488 - BUG: No length check
        p++;              // Line 2489 - p advances without checking len
    while (len != 0 && p[len - 1] == ' ')
        len--;
    copy = xstrndup(p, len);
    colour = colour_byname(copy);
    free(copy);
}
```

### Root Cause Analysis
The vulnerability exists because the first while loop (lines 2488-2489) advances the pointer `p` past leading spaces without checking or decrementing the `len` variable. This causes a buffer over-read when:

1. The input string `p` has a known length `len` (calculated from `strlen(p)` at line 2467)
2. The loop at line 2488 advances `p` past spaces without tracking how many bytes were skipped
3. Later access to `p[len - 1]` or subsequent operations use the original `len` value, which is now incorrect
4. The string pointed to by `p` is shorter than `len` after skipping spaces, causing a read beyond the allocated buffer

The POV `\033]11;               \033` (ESC ] 11 ; [15 spaces] ESC) triggers this by providing many leading spaces after the semicolon, causing `p` to advance far enough that subsequent operations read past the buffer end.

## CWE Classification
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-125**: Out-of-bounds Read
- **CWE-787**: Out-of-bounds Write (parent category)

## Vulnerability Description

The `input_osc_parse_colour` function in tmux's input.c file contains a heap buffer over-read vulnerability. The function parses color specifications from OSC (Operating System Command) escape sequences, specifically OSC 11 which sets the background color.

When parsing color names (the `else` branch starting at line 2487), the function attempts to skip leading spaces. However, the while loop that advances the pointer `p` past spaces (line 2488-2489) does not check or update the length variable `len`. This creates a discrepancy between the pointer position and the tracked length.

If an attacker provides an OSC 11 sequence with many leading spaces (e.g., `\033]11;               \033`), the pointer advances significantly while `len` remains at the original string length. Subsequent operations that use `len` to access the buffer (like checking `p[len - 1]`) will read beyond the actual allocated buffer boundaries.

**Impact**: This vulnerability allows a heap buffer over-read, which could potentially leak sensitive information from adjacent memory regions or cause a crash. While the direct security impact is limited (it's a read, not a write), it could be used as part of a more complex exploit chain.

## POV Analysis

The proof-of-vulnerability file contains 21 bytes:
```
1b 5d 31 31 3b 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 1b
\033]11;               \033
```

This translates to:
- `\033]` - OSC (Operating System Command) sequence start
- `11;` - OSC 11 command (background color query/set)
- 15 space characters (`0x20`)
- `\033` - ESC character (sequence terminator)

The vulnerability is triggered because:
1. The string after the semicolon consists entirely of spaces
2. The first while loop advances `p` past all 15 spaces
3. The original `len` is not reduced, causing subsequent array accesses to go out of bounds
4. AddressSanitizer detects the 1-byte read at line 2490

## Patch Analysis

The patch (patch_0.diff) adds proper length tracking to the space-skipping loop:

```diff
-		while (*p == ' ')
+		while (len != 0 && *p == ' ') {
 			p++;
+			len--;
+		}
```

**Fix Details**:
1. Adds a length check: `len != 0` prevents reading past the end
2. Decrements `len` each time `p` advances
3. Maintains the invariant that `len` represents the remaining valid bytes at pointer `p`

This fix ensures that `len` and `p` stay synchronized, preventing the buffer over-read. The patch mirrors the correct implementation in the subsequent while loop (line 2490) which already had proper bounds checking.

**Historical Note**: This fix was originally committed to tmux on February 18, 2021 (commit fb42ae3071763fdc6a2fe2e57feec774623b1c33) by Nicholas Marriott, then reverted for the benchmark (commit 0e2a8078).

## Recommendations
- **Suggested CWEs**: [CWE-122, CWE-125, CWE-787]
- **Vulnerability Name**: Heap Buffer Over-read in OSC Color Parameter Parsing
- **Severity**: Medium (information disclosure, potential DoS)
- **Fix Priority**: High (simple bounds check addition)