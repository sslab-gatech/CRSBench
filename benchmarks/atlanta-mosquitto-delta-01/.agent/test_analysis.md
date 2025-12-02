# Test Analysis: Mosquitto MQTT Broker

**Project**: atlanta-mosquitto-delta-01
**Repository**: `/mnt/ssd1/acorn421/team-atlanta/repos/cp-c-mosquitto-src-806fb8aa`
**Analysis Date**: 2024-11-30

---

## Executive Summary

The Mosquitto project contains an extensive test suite with:
- **411 total Python test files** across multiple test categories
- **12 C unit test files** using CUnit framework
- **21+ plugin test scripts** (shell-based)
- Support for both **Make** and **CMake** build systems
- Test execution via custom Python test runner (`ptest.py`)

---

## 1. Build System and Test Framework

### Primary Build Systems
1. **Make** (traditional Unix build)
   - Main Makefile at repository root
   - Supports: `make test`, `make check`, `make ptest` (parallel tests)
   - Used for production builds

2. **CMake** (modern cross-platform build)
   - Root CMakeLists.txt with `WITH_TESTS` option
   - GoogleTest integration for C++ tests
   - CUnit integration for C unit tests
   - Preferred for development and CI

### Test Frameworks
- **Python 3** with custom `ptest.py` test runner for integration/functional tests
- **CUnit** for C unit tests (library testing)
- **GoogleTest (GTest)** for C++ tests (configured in CMake)
- Custom test harness in `test/mosq_test.py` for broker integration tests

---

## 2. Test Directory Structure

```
test/
├── apps/                    # Application tests (23 Python files)
│   ├── ctrl/               # mosquitto_ctrl tests (3 tests)
│   ├── db_dump/            # Database dump utility tests
│   ├── passwd/             # Password utility tests
│   └── signal/             # Signal handling tests
├── broker/                  # Broker integration tests (281 Python files)
│   ├── test.py            # Main broker test suite entry point
│   ├── c/                 # C-based broker tests
│   ├── data/              # Test data files
│   └── *.py               # Individual broker test cases
├── client/                  # Client tests (39 Python files)
│   ├── test.py            # Main client test suite entry point
│   ├── data/              # Test data
│   └── *.py               # mosquitto_pub/sub client tests
├── lib/                     # Library tests (60 Python files)
│   ├── test.py            # Main library test suite entry point
│   ├── c/                 # C library tests
│   ├── cpp/               # C++ library tests
│   └── *.py               # libmosquitto API tests
├── unit/                    # C unit tests (12 C test files)
│   ├── broker/            # Broker unit tests (6 test executables)
│   │   ├── bridge_topic_test.c
│   │   ├── keepalive_test.c
│   │   ├── persist_read_test.c
│   │   ├── persist_write_test.c
│   │   ├── subs_test.c
│   │   └── *_stubs.c      # Test stubs/mocks
│   ├── lib/               # Library unit tests
│   │   ├── test.c
│   │   ├── datatype_read.c
│   │   ├── datatype_write.c
│   │   ├── property_read.c
│   │   ├── property_write.c
│   │   └── publish_test.c
│   └── libcommon/         # Common library unit tests
│       ├── test.c
│       ├── property_add.c
│       ├── property_value.c
│       ├── strings_test.c
│       ├── topic_test.c
│       ├── trim_test.c
│       └── utf8.c
├── mock/                    # Mock implementations for testing
│   ├── lib/               # Library mocks
│   └── apps/              # Application mocks
├── ssl/                     # SSL/TLS test certificates and keys
├── random/                  # Random/fuzz testing
└── old/                     # Legacy/deprecated tests
```

---

## 3. Test Categories and Files

### 3.1 Unit Tests (C/CUnit)

**Location**: `test/unit/`
**Framework**: CUnit (C unit testing framework)
**Test Executables**: 12 test files

#### Broker Unit Tests (`test/unit/broker/`)
1. **bridge_topic_test.c** - Bridge topic remapping tests
2. **keepalive_test.c** - Keep-alive timeout tests
3. **persist_read_test.c** - Persistence read functionality (29,839 lines)
4. **persist_write_test.c** - Persistence write functionality (11,683 lines)
5. **subs_test.c** - Subscription handling tests

#### Library Unit Tests (`test/unit/lib/`)
6. **test.c** - Main test runner
7. **datatype_read.c** - Data type reading tests (22,414 lines)
8. **datatype_write.c** - Data type writing tests
9. **property_read.c** - MQTT property reading (59,924 lines)
10. **property_write.c** - MQTT property writing (22,677 lines)
11. **property_user_read.c** - User property reading (28,989 lines)
12. **publish_test.c** - Publish functionality tests

#### Common Library Unit Tests (`test/unit/libcommon/`)
13. **property_add.c** - Property addition tests (27,783 lines)
14. **property_value.c** - Property value tests
15. **strings_test.c** - String handling tests
16. **topic_test.c** - Topic parsing/validation (59,541 lines)
17. **trim_test.c** - String trimming tests
18. **utf8.c** - UTF-8 validation tests (20,472 lines)

**Build Commands**:
```bash
# Via CMake (preferred)
cmake -DWITH_TESTS=ON .
make
ctest

# Via Make
make test-compile
make utest
```

---

### 3.2 Broker Integration Tests

**Location**: `test/broker/`
**Count**: 281 Python test files
**Entry Point**: `test/broker/test.py`
**Framework**: Custom Python test harness (`ptest.py`)

#### Test Categories (by number prefix):
- **01-connect-*.py** (~25 tests) - Connection handling, authentication, protocol versions
- **02-*.py** (~60 tests) - Subscribe/publish, QoS levels, topic handling
- **03-publish-*.py** (~30 tests) - Publish operations, QoS, payload handling
- **04-retain-*.py** (~10 tests) - Retained message handling
- **05-*.py** (~5 tests) - Session management, clean session
- **06-bridge-*.py** (~25 tests) - Bridge functionality
- **07-will-*.py** (~20 tests) - Will message handling
- **08-ssl-*.py** (~15 tests) - SSL/TLS functionality
- **09-*.py** (~40 tests) - ACL, authentication, plugins
- **10-*.py** (~3 tests) - Listener configurations
- **11-*.py** (~10 tests) - Persistence, subscriptions
- **12-prop-*.py** (~10 tests) - MQTT v5 properties
- **13-*.py** (~2 tests) - WebSocket support
- **14-dynsec-*.py** (~20 tests) - Dynamic security plugin
- **15-persist-*.py** (~20 tests) - Persistence with SQLite
- **16-config-*.py** (~7 tests) - Configuration parsing
- **17-control-*.py** (~2 tests) - Control interface
- **20-sparkplug-*.py** (~2 tests) - Sparkplug aware plugin
- **21-proxy-*.py** (~15 tests) - Proxy protocol support

**Example Test Files**:
```
test/broker/01-connect-allow-anonymous.py
test/broker/02-subpub-qos0.py
test/broker/03-publish-qos1.py
test/broker/08-ssl-connect-cert-auth.py
test/broker/09-plugin-auth-unpwd-success.py
test/broker/15-persist-client-v5-0.py
```

**Run Command**:
```bash
cd test/broker
./test.py
# Or for parallel execution
make ptest
```

---

### 3.3 Client Tests

**Location**: `test/client/`
**Count**: 39 Python test files
**Entry Point**: `test/client/test.py`
**Tests**: mosquitto_pub, mosquitto_sub, mosquitto_rr clients

#### Test Categories:
- **02-subscribe-*.py** (~13 tests) - Subscribe client functionality
- **03-publish-*.py** (~18 tests) - Publish client functionality
- **04-rr-*.py** (~8 tests) - Request-response client functionality

**Example Test Files**:
```
test/client/02-subscribe-qos1.py
test/client/03-publish-qos1.py
test/client/03-publish-file.py
test/client/04-rr-qos1.py
```

**Run Command**:
```bash
cd test/client
./test.py
```

---

### 3.4 Library Tests

**Location**: `test/lib/`
**Count**: 60 Python test files
**Entry Point**: `test/lib/test.py`
**Tests**: libmosquitto C library and libmosquittopp C++ library

#### Test Categories:
- **01-*.py** (~12 tests) - Connection, authentication, keepalive
- **02-*.py** (~7 tests) - Subscribe/unsubscribe
- **03-*.py** (~20 tests) - Publish operations, QoS handling
- **04-*.py** (~2 tests) - Retained messages
- **08-ssl-*.py** (~5 tests) - SSL/TLS functionality
- **09-*.py** (~2 tests) - Utility functions
- **11-prop-*.py** (~3 tests) - MQTT v5 properties

**Subdirectories**:
- `test/lib/c/` - C library specific tests
- `test/lib/cpp/` - C++ library (libmosquittopp) tests

**Run Command**:
```bash
cd test/lib
./test.py
```

---

### 3.5 Application Tests

**Location**: `test/apps/`
**Count**: 23 Python test files across 4 utilities

#### Test Suites:
1. **ctrl/** (3 tests) - mosquitto_ctrl utility tests
   - `ctrl-args.py` - Argument parsing
   - `ctrl-broker.py` - Broker control
   - `ctrl-dynsec.py` - Dynamic security control

2. **db_dump/** - mosquitto_db_dump utility tests
   - Database dump functionality

3. **passwd/** - mosquitto_passwd utility tests
   - Password file management

4. **signal/** - Signal handling tests
   - Broker signal handling (SIGHUP, SIGTERM, etc.)

**Run Command**:
```bash
cd test/apps/ctrl
./test.py
```

---

### 3.6 Plugin Tests

**Location**: `plugins/*/test.sh`
**Count**: 21+ shell test scripts
**Framework**: Bash shell scripts with custom test logic

#### Plugin Test Files:
1. **dynamic-security/test.sh** - Dynamic security plugin
2. **persist-sqlite/test.sh** - SQLite persistence plugin
3. **sparkplug-aware/test.sh** - Sparkplug protocol support
4. **examples/payload-ban/test.sh** - Payload filtering
5. **examples/payload-modification/test.sh** - Message modification
6. **examples/connection-state/test.sh** - Connection state tracking
7. **examples/topic-jail/test.sh** - Topic restrictions
8. **examples/deny-protocol-version/test.sh** - Protocol version filtering
9. **examples/force-retain/test.sh** - Force retained messages
10. **examples/auth-by-ip/test.sh** - IP-based authentication
11. **examples/topic-modification/test.sh** - Topic rewriting
12. **examples/plugin-event-stats/test.sh** - Event statistics
13. **examples/add-properties/test.sh** - Property addition
14. **examples/wildcard-temp/test.sh** - Wildcard temperature handling
15. **examples/payload-size-stats/test.sh** - Payload statistics
16. **examples/print-ip-on-publish/test.sh** - IP logging
17. **examples/message-timestamp/test.sh** - Message timestamping
18. **examples/limit-subscription-qos/test.sh** - QoS limiting
19. **examples/client-lifetime-stats/test.sh** - Client statistics
20. **examples/delayed-auth/test.sh** - Delayed authentication
21. **examples/client-properties/test.sh** - Client property handling

**Run Command**:
```bash
cd plugins/<plugin-name>
./test.sh
# Or via make
make -C plugins test
```

---

## 4. Test Execution Commands

### 4.1 Main Test Commands

```bash
# Run all tests (sequential)
make test
make check  # Alias for 'make test'

# Run tests in parallel (faster, up to 20 concurrent)
make ptest

# Run only unit tests (C/CUnit)
make utest

# Run via Python test runner
python3 run_tests.py

# Build test binaries without running
make test-compile
```

### 4.2 CMake Test Commands

```bash
# Configure with tests enabled
cmake -DWITH_TESTS=ON .

# Build all tests
make

# Run all tests via CTest
ctest

# Run tests with verbose output
ctest -V

# Run specific test
ctest -R unit-lib-test

# Generate test coverage
make coverage
```

### 4.3 Individual Test Suite Commands

```bash
# Broker tests
cd test/broker && ./test.py
make -C test/broker test
make -C test/broker ptest  # Parallel

# Client tests
cd test/client && ./test.py
make -C test/client test

# Library tests
cd test/lib && ./test.py
make -C test/lib test

# Application tests
cd test/apps/ctrl && ./test.py
make -C test/apps test

# Unit tests
cd test/unit
make test
# Or via CMake
ctest -R "unit-*"

# Plugin tests
make -C plugins test
```

---

## 5. Test Dependencies

### Required Packages
- **Python 3** - Test runner and integration tests
- **CUnit** - C unit testing framework
- **GoogleTest** - C++ testing framework (optional)
- **OpenSSL** - SSL/TLS tests
- **cJSON** - JSON handling (for dynamic security tests)

### Build-Time Requirements
From `README-tests.md`:
```
The tests require Python 3 and CUnit to be installed.
```

### Runtime Requirements
- Running `mosquitto` broker binary
- Test certificates in `test/ssl/`
- Network ports (tests allocate 1-4 ports dynamically)
- Temporary file access for persistence tests

---

## 6. Test File Patterns

### 6.1 Python Integration Tests
**Pattern**: `test/{broker,client,lib,apps}/**/*.py`
**Total**: ~380 files

**Naming Conventions**:
- `XX-category-description.py` where XX is test category number
- Examples:
  - `01-connect-*.py` - Connection tests
  - `02-subscribe-*.py` - Subscribe tests
  - `03-publish-*.py` - Publish tests
  - `08-ssl-*.py` - SSL/TLS tests
  - `09-plugin-*.py` - Plugin tests

### 6.2 C Unit Tests
**Pattern**: `test/unit/**/*test.c`
**Total**: ~12 primary test files + ~8 stub files

**Naming Conventions**:
- `*_test.c` - Test implementations
- `*_stubs.c` - Mock/stub implementations
- `test.c` - Test runner main

### 6.3 Test Helpers
**Pattern**: `test/**/mosq_test*.py`, `test/**/test.py`

**Key Helper Files**:
- `test/mosq_test.py` - Main test helper (42,707 lines)
- `test/ptest.py` - Parallel test runner
- `test/mqtt5_props.py` - MQTT v5 properties
- `test/mqtt5_rc.py` - MQTT v5 return codes
- `test/broker/mosq_test_helper.py` - Broker test utilities
- `test/client/mosq_test_helper.py` - Client test utilities

---

## 7. Patch Exclude List

### 7.1 Complete Test Directory Exclusions

The following directories should be **completely excluded** from patching as they contain only test code:

```
test/
test/apps/
test/apps/ctrl/
test/apps/db_dump/
test/apps/passwd/
test/apps/signal/
test/broker/
test/broker/c/
test/broker/data/
test/client/
test/client/data/
test/lib/
test/lib/c/
test/lib/cpp/
test/lib/data/
test/unit/
test/unit/broker/
test/unit/broker/files/
test/unit/lib/
test/unit/libcommon/
test/mock/
test/mock/lib/
test/mock/apps/
test/old/
test/random/
test/ssl/
```

### 7.2 Test File Patterns to Exclude

Exclude all files matching these patterns:

```
**/*test*.c
**/*test*.cpp
**/*test*.py
**/*_stubs.c
**/test.sh
**/test.conf
test/**/*.py
test/**/*.c
test/**/*.cpp
test/**/*.h
plugins/**/test.sh
plugins/**/test.conf
```

### 7.3 Specific Test Files

```
# Root level test files
run_tests.py
buildtest.py

# Test documentation
README-tests.md

# Test utilities
test/ptest.py
test/mosq_test.py
test/mqtt5_opts.py
test/mqtt5_props.py
test/mqtt5_rc.py
test/path_helper.h
test/__init__.py

# Broker test files (281 files)
test/broker/*.py
test/broker/test.py
test/broker/mosq_test_helper.py
test/broker/msg_sequence_test.py
test/broker/ntest.py
test/broker/persist_module_helper.py
test/broker/persist_sqlite.py
test/broker/prop_subpub_helper.py

# Client test files (39 files)
test/client/*.py
test/client/test.py
test/client/mosq_test_helper.py

# Library test files (60 files)
test/lib/*.py
test/lib/test.py
test/lib/msg_sequence_test.py

# Application test files (23 files)
test/apps/**/*.py
test/apps/ctrl/test.py
test/apps/db_dump/test.py
test/apps/passwd/test.py
test/apps/signal/test.py

# Unit test files
test/unit/**/*.c
test/unit/**/*.h
test/unit/**/CMakeLists.txt
test/unit/**/Makefile

# Plugin tests
plugins/dynamic-security/test.sh
plugins/dynamic-security/test.conf
plugins/persist-sqlite/test.sh
plugins/persist-sqlite/test.conf
plugins/sparkplug-aware/test.sh
plugins/sparkplug-aware/test.conf
plugins/examples/*/test.sh
plugins/examples/*/test.conf

# Test data and configuration
test/broker/data/**
test/client/data/**
test/lib/data/**
test/ssl/**
test/unit/broker/files/**
```

### 7.4 Test Build Configuration

```
# Test-related Makefile targets
test/Makefile
test/unit/Makefile
test/broker/Makefile
test/client/Makefile
test/lib/Makefile
test/apps/Makefile
test/mock/Makefile

# Test-related CMake files
test/CMakeLists.txt
test/unit/CMakeLists.txt
test/broker/CMakeLists.txt
test/client/CMakeLists.txt
test/lib/CMakeLists.txt
test/apps/CMakeLists.txt
test/mock/CMakeLists.txt
```

---

## 8. Test Coverage Analysis

### Test Distribution by Component

| Component | Python Tests | C Unit Tests | Plugin Tests | Total |
|-----------|-------------|--------------|--------------|-------|
| Broker | 281 | 5 | - | 286 |
| Library | 60 | 7 | - | 67 |
| Client | 39 | - | - | 39 |
| Apps | 23 | - | - | 23 |
| Plugins | - | - | 21 | 21 |
| **Total** | **403** | **12** | **21** | **436+** |

### Test Complexity

**Largest Test Files**:
1. `test/unit/lib/property_read.c` - 59,924 lines
2. `test/unit/libcommon/topic_test.c` - 59,541 lines
3. `test/mosq_test.py` - 42,707 lines
4. `test/unit/broker/persist_read_test.c` - 29,839 lines
5. `test/unit/lib/property_user_read.c` - 28,989 lines
6. `test/unit/libcommon/property_add.c` - 27,783 lines

**Test Coverage Areas**:
- ✅ MQTT v3.1.1 protocol compliance
- ✅ MQTT v5.0 protocol compliance
- ✅ SSL/TLS security
- ✅ Authentication and ACL
- ✅ Plugin system
- ✅ Persistence (both file and SQLite)
- ✅ Bridging
- ✅ WebSocket support
- ✅ Quality of Service (QoS 0, 1, 2)
- ✅ Will messages
- ✅ Retained messages
- ✅ Clean/persistent sessions
- ✅ Client libraries (C and C++)
- ✅ Command-line utilities

---

## 9. Recommendations for CRS Patching

### 9.1 Exclude Strategy

**CRITICAL**: Do NOT patch any files under `test/` directory or matching test patterns.

**Rationale**:
1. Tests validate bug fixes - modifying them defeats the purpose
2. Test code is not part of production codebase
3. 436+ test files represent significant false positive risk
4. Tests use different coding standards (mocking, stubs, etc.)

### 9.2 Patch Focus Areas

Focus CRS patching efforts on:

```
# Production source code
src/**/*.c          # Broker implementation
lib/**/*.c          # Client library
libcommon/**/*.c    # Common utilities
client/**/*.c       # Client applications
apps/**/*.c         # Utility applications
plugins/**/*.c      # Plugin implementations (excluding test.sh)

# Headers
include/**/*.h
src/**/*.h
lib/**/*.h
```

### 9.3 Validation Strategy

After applying patches:

```bash
# 1. Ensure tests still compile
make test-compile

# 2. Run unit tests
make utest

# 3. Run integration tests (selective)
cd test/broker && ./test.py --rerun-failed

# 4. Run full test suite
make ptest
```

### 9.4 Test Exclusion Regex

For automated CRS patch exclusion:

```regex
# Exclude test directories
^test/.*

# Exclude test files
.*test\.c$
.*test\.cpp$
.*test\.py$
.*_test\.c$
.*_stubs\.c$

# Exclude test scripts
.*/test\.sh$
.*/test\.conf$

# Exclude test utilities
run_tests\.py
buildtest\.py
ptest\.py
mosq_test\.py
```

---

## 10. Summary

### Test Suite Characteristics

- **Total Test Files**: 436+ (excluding test data)
- **Test Lines of Code**: ~500,000+ lines
- **Test Frameworks**: Python 3, CUnit, GoogleTest
- **Build Systems**: Make + CMake
- **Test Execution**: Serial (~1 hour) or Parallel (~10 minutes)
- **Coverage**: Comprehensive across all MQTT features

### Key Exclusions for Patching

1. **Entire `test/` directory tree** - 380+ Python files, 12+ C test files
2. **All `*test*.c` and `*test*.py` files**
3. **All `test.sh` scripts** - 21+ plugin tests
4. **Test helper files** - `ptest.py`, `mosq_test.py`, etc.
5. **Test data directories** - `test/*/data/`, `test/ssl/`
6. **Mock/stub implementations** - `test/mock/`, `*_stubs.c`

### Critical Recommendations

✅ **DO**: Patch production code in `src/`, `lib/`, `client/`, `apps/`
❌ **DON'T**: Patch anything under `test/` directory
❌ **DON'T**: Modify files matching `*test*.{c,py}` patterns
❌ **DON'T**: Touch plugin `test.sh` scripts
✅ **DO**: Run test suite after patching to validate fixes

---

**End of Analysis**
