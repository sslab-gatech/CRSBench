# test.sh Rationale for atlanta-netty-delta-01

## Project Overview
- **Project**: Netty - asynchronous event-driven network application framework
- **Language**: Java (JVM)
- **Build System**: Maven
- **Test Framework**: JUnit 5

## Test Strategy

### Selected Tests
The test.sh script runs a focused set of unit tests from the buffer module:
- `ByteBufUtilTest` - Tests for ByteBuf utility functions (177 tests)
- `EmptyByteBufTest` - Tests for empty ByteBuf handling (9 tests)
- `IntPriorityQueueTest` - Tests for integer priority queue (5 tests)

Total: ~191 tests

### Rationale for Test Selection

1. **Speed**: These tests are fast-running unit tests that complete in ~8 seconds
2. **Coverage**: The buffer module is core to Netty's functionality and well-tested
3. **Reliability**: These tests are stable and don't require network resources or long timeouts
4. **Dependencies**: The buffer module only depends on the common module, minimizing build time

### Build Approach

The script uses a two-phase approach:

1. **Phase 1 - Build Dependencies**:
   ```bash
   mvn install -Dcheckstyle.skip=true -DskipTests -pl common -am
   ```
   - Builds and installs the common module (dependency of buffer)
   - Skips checkstyle to avoid style violations
   - Skips tests during dependency build

2. **Phase 2 - Run Tests**:
   ```bash
   mvn test -Dcheckstyle.skip=true -pl buffer -Dtest=ByteBufUtilTest,EmptyByteBufTest,IntPriorityQueueTest
   ```
   - Runs only the specified test classes in the buffer module
   - Fast execution time (~8 seconds)

### Why Not Run All Tests?

Running the full test suite would:
- Take too long (would timeout at 120 seconds)
- Include integration tests that require network resources
- Include SSL/TLS tests that can be flaky in containers
- Test modules that aren't relevant to core buffer functionality

### Execution Environment

- **Container WORKDIR**: `/src/netty`
- **test.sh location**: `/src/test.sh`
- **Maven executable**: `/src/maven-3.6.3/apache-maven-3.6.3/bin/mvn`
- **Execution**: test.sh is run from the netty project root

## Test Output

Expected output:
```
[INFO] Tests run: 191, Failures: 0, Errors: 0, Skipped: 9
[INFO] BUILD SUCCESS
```

The tests validate critical buffer functionality including:
- Byte buffer allocation and management
- Buffer utility functions (encoding, decoding, etc.)
- Empty buffer edge cases
- Priority queue operations
