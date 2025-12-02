# test.sh Rationale for atlanta-geonetwork-delta-01

## Summary
The test.sh script runs Maven unit tests for the GeoNetwork core module, which contains 116 tests covering various kernel functionalities.

## Execution Environment
- **WORKDIR**: `/src/src/cp-java-geonetwork-source`
- **test.sh location**: `/src/test.sh`
- **Maven**: Available at `/usr/bin/mvn`

## Test Strategy
The script uses `mvn test -pl core -am -DskipTests=false` to:
- Run tests only for the `core` module (`-pl core`)
- Build dependent modules first (`-am` = also make)
- Explicitly enable tests (`-DskipTests=false`)

## Test Coverage
The core module tests include:
- Thesaurus management tests (AllThesaurusTest: 38 tests)
- Keyword search tests (KeywordsSearcherTest: 20 tests)
- RDF query builder tests (QueryBuilderTest: 6 tests)
- LDAP role converter tests (4 tests)
- Search and indexing functionality
- Security and authentication components

Total: **116 tests** (115 passed, 1 skipped)

## Why Core Module
1. **Comprehensive coverage**: The core module contains the most critical functionality
2. **Fast execution**: Completes in ~5 minutes
3. **Well-maintained**: All tests pass reliably
4. **No external dependencies**: Tests use H2 in-memory database
5. **Representative**: Tests cover key components that bad_patch.diff can target

## Verification
- Build time: ~4:41 minutes
- All tests pass: ✅
- Return code: 0 (success)
