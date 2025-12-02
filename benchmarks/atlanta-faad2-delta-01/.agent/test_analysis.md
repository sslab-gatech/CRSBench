# Test Analysis for cp-c-faad2-2ea4a353

**Project**: FAAD2 (Freeware Advanced Audio (AAC) Decoder)
**Repository**: `/mnt/ssd1/acorn421/team-atlanta/repos/cp-c-faad2-2ea4a353`
**Benchmark**: `benchmarks/atlanta-faad2-delta-01`
**Analysis Date**: 2024-11-30

---

## Executive Summary

This project is an OSS-Fuzz integrated AAC audio decoder library with **no traditional unit tests**. All testing is performed through **fuzz testing harnesses** that serve as functional tests for the library. The project uses Bazel as its build system with support for OSS-Fuzz integration.

**Key Findings**:
- ✅ No unit test files to exclude from patching
- ✅ 2 fuzz harness files identified (functional tests only)
- ✅ Build system: Bazel with CMake support
- ✅ Test framework: OSS-Fuzz fuzzing infrastructure (libFuzzer)
- ✅ Frontend CLI application exists but is not a test program

---

## 1. Build System and Test Framework

### Build System
- **Primary**: Bazel 7.4.0
- **Secondary**: CMake 3.15+ (for standalone builds)
- **OSS-Fuzz Integration**: Yes (`.oss-fuzz/build.sh`)

### Build Files
```
BUILD.bazel              # Bazel build configuration
CMakeLists.txt           # CMake build configuration
WORKSPACE.bazel          # Bazel workspace
workspace.bzl            # Bazel workspace helper
.bazelrc                 # Bazel configuration
```

### Test Framework
- **Framework**: OSS-Fuzz (libFuzzer-based fuzzing)
- **Sanitizers Supported**:
  - AddressSanitizer (ASAN)
  - UndefinedBehaviorSanitizer (UBSAN)
  - MemorySanitizer (MSAN)
- **Fuzzing Engines**: libFuzzer

### CI/CD Integration
The project has GitHub Actions workflows:
- `.github/workflows/build.yaml` - Build verification (Bazel, CMake, MSVC, OSX, MSYS)
- `.github/workflows/fuzz.yaml` - OSS-Fuzz CI integration with all sanitizers

---

## 2. Test Files Identification

### 2.1 Unit Test Files
**Result**: ❌ **No unit test files found**

The project does not contain any traditional unit test files. The codebase was searched for:
- Files matching `*test*.c`, `*test*.cpp`, `*test*.h`
- Directories named `test/`, `tests/`, `spec/`, `check/`
- Test-related function names in source code

**No matches found.**

### 2.2 Fuzz Test Harnesses (Functional Tests)

The project contains **2 fuzz harness files** in the `fuzz/` directory:

#### File 1: `fuzz/fuzz_config.c`
```
Path: /mnt/ssd1/acorn421/team-atlanta/repos/cp-c-faad2-2ea4a353/fuzz/fuzz_config.c
LOC: 62 lines
Purpose: Tests configuration and utility APIs
Functions Tested:
  - NeAACDecGetErrorMessage()
  - NeAACDecGetVersion()
  - NeAACDecGetCapabilities()
  - NeAACDecAudioSpecificConfig()
```

**Test Targets**:
- `fuzz_config` (base version, no variants)

#### File 2: `fuzz/fuzz_decode.c`
```
Path: /mnt/ssd1/acorn421/team-atlanta/repos/cp-c-faad2-2ea4a353/fuzz/fuzz_decode.c
LOC: 124 lines
Purpose: Tests audio decoding functionality with various configurations
Functions Tested:
  - NeAACDecOpen()
  - NeAACDecSetConfiguration()
  - NeAACDecGetCurrentConfiguration()
  - NeAACDecInit() / NeAACDecInit2()
  - NeAACDecInitDRM() (if DRM_SUPPORT defined)
  - NeAACDecPostSeekReset()
  - NeAACDecDecode() / NeAACDecDecode2()
  - NeAACDecClose()
```

**Test Targets** (with build variants):
- `fuzz_decode` (standard)
- `fuzz_decode_drm` (with DRM_SUPPORT)
- `fuzz_decode_fixed` (with FIXED_POINT)
- `fuzz_decode_drm_fixed` (with DRM_SUPPORT + FIXED_POINT)

### 2.3 Frontend Application (Not a Test)

#### File: `frontend/main.c`
```
Path: /mnt/ssd1/acorn421/team-atlanta/repos/cp-c-faad2-2ea4a353/frontend/main.c
LOC: ~1200 lines
Purpose: Command-line AAC/MP4 decoder application
Status: NOT A TEST - This is a production CLI tool
```

This is **not a test file**. It's the main command-line interface for the FAAD2 decoder library, similar to how `ffmpeg` is a CLI for libav libraries.

**Other Frontend Files**:
- `frontend/audio.c` - Audio output handling
- `frontend/mp4read.c` - MP4 container parsing
- `frontend/getopt.c` - Command-line option parsing (getopt implementation)
- `frontend/unicode_support.c` - Unicode filename support

---

## 3. Library Source Structure

### Core Library: `libfaad/`
The main AAC decoder library contains 43 C source files:

**Categories**:
- **Decoder Core**: `decoder.c`, `syntax.c`, `specrec.c`
- **Bitstream**: `bits.c`, `huffman.c`
- **DSP/Transform**: `cfft.c`, `mdct.c`, `filtbank.c`
- **AAC Features**: `tns.c`, `pns.c`, `lt_predict.c`, `ic_predict.c`
- **SBR (HE-AAC)**: `sbr_*.c` (13 files)
- **PS (Parametric Stereo)**: `ps_*.c` (2 files)
- **DRM**: `drm_dec.c`
- **Output**: `output.c`
- **Error Handling**: `error.c`, `common.c`
- **Format Support**: `mp4.c`

**Total**: 43 C files + corresponding headers

---

## 4. Test Commands

### 4.1 Build Commands (via Bazel)

```bash
# Build all fuzz tests
bazel build :all

# Build specific fuzz target
bazel build //:fuzz_config
bazel build //:fuzz_decode
bazel build //:fuzz_decode_drm
bazel build //:fuzz_decode_fixed
bazel build //:fuzz_decode_drm_fixed
```

### 4.2 Run Fuzz Tests

```bash
# Run fuzz_config with ASAN
bazel run --config=asan-libfuzzer //:fuzz_config_run

# Run fuzz_decode with ASAN
bazel run --config=asan-libfuzzer //:fuzz_decode_run

# Run with UBSAN
bazel run --config=ubsan-libfuzzer //:fuzz_decode_run

# Run with MSAN
bazel run --config=msan-libfuzzer //:fuzz_decode_run
```

### 4.3 OSS-Fuzz Build

```bash
# Build via OSS-Fuzz (used in CI)
cd .oss-fuzz
./build.sh

# This invokes: bazel_build_fuzz_tests
```

### 4.4 CMake Build (Alternative)

```bash
# Standard build
cmake -B build .
cmake --build build

# Build frontend CLI
cmake -B build . -DFAAD_BUILD_CLI=ON
cmake --build build
```

**Note**: CMake does not build fuzz tests. Only Bazel builds fuzz tests.

---

## 5. Test File Exclusions for Patching

### 5.1 Files to Exclude

Since there are **no unit test files**, the exclusion list focuses on:
1. **Fuzz harness files** (functional tests)
2. **Build system files**
3. **Documentation**
4. **CI/CD configuration**

### 5.2 Comprehensive Patch Exclude List

```yaml
patch_exclude_list:
  # Build system files
  - build.sh
  - .oss-fuzz/build.sh
  - Makefile
  - CMakeLists.txt
  - BUILD.bazel
  - WORKSPACE.bazel
  - workspace.bzl
  - .bazelrc
  - configure
  - configure.ac
  - '*.ac'
  - '*.am'
  - properties.json

  # Fuzz test harnesses (functional tests)
  - fuzz/**
  - fuzz/fuzz_config.c
  - fuzz/fuzz_decode.c

  # Frontend CLI application (not library code)
  - frontend/**
  - frontend/*.c
  - frontend/*.h

  # Documentation
  - docs/**
  - '*.md'
  - README*
  - AUTHORS
  - COPYING
  - ChangeLog

  # CI/CD and version control
  - .github/**
  - .git/**
  - .gitignore

  # OSS-Fuzz and benchmark metadata
  - .oss-fuzz/**
  - .aixcc/**

  # Test patterns (defensive, though no tests exist)
  - '**/*test*.c'
  - '**/*test*.cc'
  - '**/*test*.cpp'
  - '**/*test*.h'
  - test/**
  - tests/**
```

### 5.3 Rationale for Exclusions

| Category | Rationale |
|----------|-----------|
| `fuzz/**` | Fuzz harnesses are functional tests, not production code |
| `frontend/**` | CLI application, not library code; vulnerabilities are in libfaad |
| Build files | Should not be modified by automated patching |
| Docs/README | Non-code files |
| `.oss-fuzz/**` | OSS-Fuzz integration and benchmark metadata |
| `.aixcc/**` | CRSBench vulnerability metadata |

---

## 6. Vulnerability Context

### Known Vulnerabilities in Benchmark

From `.oss-fuzz/.aixcc/meta.yaml`:

#### CPV 0: Integer Overflow in `fuzz_decode_fixed`
- **Harness**: `fuzz_decode_fixed`
- **POV**: `pov_0.blob`
- **Sanitizer**: UndefinedBehaviorSanitizer
- **Error**: "runtime error: signed integer overflow"
- **Commit**: Between base `f3a2fc37` and ref `2ea4a353`

#### CPV 1: AddressSanitizer Error in `fuzz_decode_drm_fixed`
- **Harness**: `fuzz_decode_drm_fixed`
- **POV**: `pov_0.blob`
- **Sanitizer**: AddressSanitizer
- **Error**: "ERROR: AddressSanitizer: ILL"
- **Commit**: Between base `f3a2fc37` and ref `2ea4a353`

**Note**: Both vulnerabilities are in the library code (`libfaad/`), not in test files.

---

## 7. Patchable Source Files

### Library Files (Patchable)
All 43 C files in `libfaad/` are patchable:

```
libfaad/analysis.h
libfaad/bits.c
libfaad/bits.h
libfaad/cfft.c
libfaad/cfft.h
libfaad/cfft_tab.h
libfaad/common.c
libfaad/common.h
libfaad/decoder.c
libfaad/drc.c
libfaad/drc.h
libfaad/drm_dec.c
libfaad/drm_dec.h
libfaad/error.c
libfaad/error.h
libfaad/filtbank.c
libfaad/filtbank.h
libfaad/fixed.h
libfaad/hcr.c
libfaad/huffman.c
libfaad/huffman.h
libfaad/ic_predict.c
libfaad/ic_predict.h
libfaad/iq_table.h
libfaad/is.c
libfaad/is.h
libfaad/kbd_win.h
libfaad/lt_predict.c
libfaad/lt_predict.h
libfaad/mdct.c
libfaad/mdct.h
libfaad/mdct_tab.h
libfaad/mp4.c
libfaad/mp4.h
libfaad/ms.c
libfaad/ms.h
libfaad/output.c
libfaad/output.h
libfaad/pns.c
libfaad/pns.h
libfaad/ps_dec.c
libfaad/ps_dec.h
libfaad/ps_syntax.c
libfaad/ps_tables.h
libfaad/pulse.c
libfaad/pulse.h
libfaad/rvlc.c
libfaad/rvlc.h
libfaad/sbr_dct.c
libfaad/sbr_dct.h
libfaad/sbr_dec.c
libfaad/sbr_dec.h
libfaad/sbr_e_nf.c
libfaad/sbr_e_nf.h
libfaad/sbr_fbt.c
libfaad/sbr_fbt.h
libfaad/sbr_hfadj.c
libfaad/sbr_hfadj.h
libfaad/sbr_hfgen.c
libfaad/sbr_hfgen.h
libfaad/sbr_huff.c
libfaad/sbr_huff.h
libfaad/sbr_noise.h
libfaad/sbr_qmf.c
libfaad/sbr_qmf.h
libfaad/sbr_qmf_c.h
libfaad/sbr_syntax.c
libfaad/sbr_syntax.h
libfaad/sbr_tf_grid.c
libfaad/sbr_tf_grid.h
libfaad/sine_win.h
libfaad/specrec.c
libfaad/specrec.h
libfaad/ssr.c
libfaad/ssr.h
libfaad/ssr_fb.c
libfaad/ssr_fb.h
libfaad/ssr_ipqf.c
libfaad/ssr_ipqf.h
libfaad/ssr_win.h
libfaad/structs.h
libfaad/syntax.c
libfaad/syntax.h
libfaad/tns.c
libfaad/tns.h
```

Plus codebook headers:
```
libfaad/codebook/*.h
```

### Header Files (Patchable)
```
include/neaacdec.h
include/faad.h.in
```

---

## 8. Testing Strategy for CRS

### 8.1 How to Verify Patches

Since there are no unit tests, patch verification must use the fuzz harnesses:

```bash
# 1. Build with patch applied
bazel build :all

# 2. Run fuzz harness with POV
bazel run --config=asan-libfuzzer //:fuzz_decode_fixed_run < pov_0.blob

# 3. Check for crash/error (should not crash after patch)
echo $?  # Should be 0 (success)
```

### 8.2 Regression Testing

Run all fuzz harness variants:
```bash
for target in fuzz_config fuzz_decode fuzz_decode_drm fuzz_decode_fixed fuzz_decode_drm_fixed; do
  bazel run --config=asan-libfuzzer //:${target}_run -- -max_total_time=60
done
```

### 8.3 POV Verification

For CRSBench evaluation:
```bash
# CPV 0 verification (fuzz_decode_fixed)
./fuzz_decode_fixed < .oss-fuzz/.aixcc/fuzz_decode_fixed/cpv_0/blobs/pov_0.blob

# CPV 1 verification (fuzz_decode_drm_fixed)
./fuzz_decode_drm_fixed < .oss-fuzz/.aixcc/fuzz_decode_drm_fixed/cpv_1/blobs/pov_0.blob
```

Expected:
- **Before patch**: Crash/error detected by sanitizer
- **After patch**: Clean exit (exit code 0)

---

## 9. Recommendations for CRS

### 9.1 Patch Generation Strategy

1. **Focus on `libfaad/` directory** - All vulnerabilities are in library code
2. **Exclude frontend/** - CLI application, not part of core library
3. **Exclude fuzz/** - Test harnesses, not production code
4. **Use fuzz harnesses for validation** - Only way to verify patches

### 9.2 Common Vulnerability Patterns

Based on the project structure and known CVEs:

| Pattern | Files to Check | Reason |
|---------|----------------|--------|
| Integer overflow | `fixed.h`, `*_tab.h` | Fixed-point arithmetic tables |
| Buffer overflow | `bits.c`, `huffman.c` | Bitstream parsing |
| Memory corruption | `decoder.c`, `syntax.c` | Main decoder logic |
| Division by zero | `sbr_*.c`, `ps_*.c` | DSP calculations |
| NULL dereference | `output.c`, `mp4.c` | Format handling |

### 9.3 Build Variants to Consider

The project builds 4 library variants:
1. `faad` (base)
2. `faad_drm` (+DRM_SUPPORT)
3. `faad_fixed` (+FIXED_POINT)
4. `faad_drm_fixed` (+DRM_SUPPORT +FIXED_POINT)

**Ensure patches work for all variants**, especially:
- FIXED_POINT builds (use integer arithmetic instead of floating-point)
- DRM_SUPPORT builds (additional code paths)

---

## 10. Summary Statistics

| Metric | Count |
|--------|-------|
| **Unit test files** | 0 |
| **Fuzz harness files** | 2 |
| **Fuzz test targets** | 5 (1 config + 4 decode variants) |
| **Library source files** | 43 C files |
| **Frontend files** | 6 C files (CLI, not library) |
| **Total patchable files** | 43 (libfaad only) |
| **Build systems** | 2 (Bazel primary, CMake secondary) |
| **Sanitizers supported** | 3 (ASAN, UBSAN, MSAN) |
| **Known vulnerabilities** | 2 (cpv_0, cpv_1) |

---

## 11. Conclusion

This FAAD2 project follows OSS-Fuzz best practices with **fuzzing as the sole testing methodology**. There are:
- ✅ **0 unit test files** - nothing to exclude for testing reasons
- ✅ **2 fuzz harnesses** - must be excluded from patching
- ✅ **1 CLI application** - should be excluded (not library code)
- ✅ **Clear separation** - all library code in `libfaad/`, tests in `fuzz/`

The patch exclude list should focus on **build files, test harnesses, and the frontend CLI**, while allowing all `libfaad/` files to be patchable.

---

## Appendices

### A. File Tree Summary
```
cp-c-faad2-2ea4a353/
├── libfaad/              # LIBRARY CODE (PATCHABLE)
│   ├── *.c               # 43 source files
│   ├── *.h               # Headers
│   └── codebook/         # Huffman codebooks
├── fuzz/                 # FUZZ TESTS (EXCLUDE)
│   ├── fuzz_config.c
│   └── fuzz_decode.c
├── frontend/             # CLI APP (EXCLUDE)
│   ├── main.c
│   ├── audio.c
│   ├── mp4read.c
│   └── ...
├── include/              # PUBLIC HEADERS (PATCHABLE)
│   ├── faad.h.in
│   └── neaacdec.h
├── docs/                 # DOCS (EXCLUDE)
├── .oss-fuzz/            # OSS-FUZZ (EXCLUDE)
├── .aixcc/               # BENCHMARK (EXCLUDE)
├── BUILD.bazel           # BUILD FILES (EXCLUDE)
├── CMakeLists.txt        # BUILD FILES (EXCLUDE)
└── .github/              # CI/CD (EXCLUDE)
```

### B. Test Discovery Commands Used

```bash
# Find test files
find . -name "*test*" -type f
find . -type d -name "test*"

# Search for test functions
grep -r "TEST\|test_" --include="*.c" --include="*.cpp"

# Find build files
find . -name "Makefile*" -o -name "CMakeLists.txt" -o -name "BUILD*"

# Count source files
find . -name "*.c" -o -name "*.cpp" | wc -l
```

### C. References

- **OSS-Fuzz Project Page**: https://github.com/google/oss-fuzz/tree/master/projects/faad2
- **Project Homepage**: https://sourceforge.net/projects/faac/
- **Build System**: Bazel (https://bazel.build/)
- **Fuzzing Engine**: libFuzzer (https://llvm.org/docs/LibFuzzer.html)

---

**Analysis Complete** ✅
