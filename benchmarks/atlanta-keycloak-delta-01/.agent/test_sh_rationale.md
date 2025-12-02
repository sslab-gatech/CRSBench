# test.sh Rationale for atlanta-keycloak-delta-01

## Project Overview
- **Project**: Keycloak - Open Source Identity and Access Management
- **Language**: Java (JVM)
- **Build System**: Maven
- **Test Framework**: JUnit

## Test Strategy

### Selected Test Modules
The test.sh script runs unit tests for the following core Keycloak modules:

1. **common** - Common utilities and helper classes
   - 15 test files
   - Tests for utilities like HtmlUtils, Base64, PathMatcher, StringPropertyReplacer, etc.

2. **core** - Core Keycloak functionality
   - 41 test files
   - Tests for JWT/JOSE parsing, token verification, cryptographic operations

3. **saml-core** - SAML protocol implementation
   - Tests for SAML parsing, validation, and XML utilities

### Why These Modules?
These modules were chosen because they:
- Have standalone unit tests that don't require external services
- Test core functionality that is critical to Keycloak's security
- Can be compiled and tested independently using Maven's `-pl` (project list) flag
- Don't require the full distribution build (which has proto schema validation issues)

### Test Execution Approach
- Use `mvn clean test -pl <module> -am -B` for each module
- The `-am` flag builds dependencies ("also make")
- The `-B` flag runs in batch mode (non-interactive)
- Each module is tested separately to isolate failures

### Build Environment
- Maven 3.6.3 is used (available as `$MVN` in the container)
- Java 17 (openjdk-17-jdk)
- MAVEN_OPTS set for sufficient memory: `-Xmx2048m -XX:MaxMetaspaceSize=512m`

## Test Coverage
The selected tests cover:
- HTML escaping and encoding (security-critical)
- Base64 encoding/decoding
- JWT/JOSE token parsing and validation
- Cryptographic operations
- SAML parsing and validation
- Path matching and URL handling

These are all functionality tests that verify correct behavior and would detect regressions from code changes.

## Alternative Approaches Considered
1. **Full build with `mvn install`** - Rejected because it requires proto schema validation and full distribution build, which adds complexity and time
2. **Integration tests** - Rejected because they require external services (databases, caches)
3. **All module tests** - Rejected because some modules depend on the full distribution or have complex dependencies
