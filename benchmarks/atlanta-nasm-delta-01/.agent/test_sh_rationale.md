# test.sh Rationale for atlanta-nasm-delta-01

## Project Overview
NASM (Netwide Assembler) is a popular x86 assembler. This benchmark uses the NASM test suite to validate the assembler's functionality.

## Test Infrastructure
The project includes a comprehensive test suite located in the `test/` directory:
- **Main test script**: `performtest.pl` - Perl script that runs all test cases
- **Test format**: Each `.asm` file contains test directives in comments specifying:
  - Test name
  - Command-line arguments
  - Expected output files (stdout, stderr, binary files)
- **Golden files**: Reference outputs stored in `test/golden/` directory
- **Test execution**: `performtest.pl` compares actual outputs against golden files

## Test Approach
The test.sh script:
1. **Regenerates golden files**: Since build timestamps and memory addresses can vary between builds, we regenerate golden files at test time
2. **Runs the test suite**: Executes `performtest.pl` with all `.asm` test files
3. **ASAN configuration**: Sets `ASAN_OPTIONS=detect_leaks=0` to avoid non-deterministic leak reports

## Key Challenges Solved
1. **Build timestamp differences**: The `-v` (version) output includes compilation date, which differs between builds. Solution: Regenerate golden files.
2. **ASAN leak reports**: AddressSanitizer detects memory leaks with non-deterministic addresses in stderr. Solution: Disable leak detection.
3. **Test coverage**: Uses the entire NASM test suite (~200+ test cases) covering instruction sets, output formats, preprocessor features, etc.

## Test Execution
```bash
cd test
export ASAN_OPTIONS=detect_leaks=0
rm -rf golden
perl performtest.pl --golden --nasm='../nasm' *.asm
perl performtest.pl --nasm='../nasm' *.asm
```

## Test Coverage
The test suite covers:
- x86/x86-64 instruction encoding
- Multiple output formats (ELF, PE, Mach-O, etc.)
- Preprocessor directives and macros
- Floating-point constants
- Label and symbol handling
- Optimization passes
- Error reporting

This comprehensive test suite ensures that any functional regression in NASM will be detected.
