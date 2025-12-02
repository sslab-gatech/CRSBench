# Test Analysis for GeoNetwork Project

## Project Overview

- **Repository**: `/home/acorn421/work/team-atlanta/afc-repos/cp-java-geonetwork-source-b74bc488`
- **Build System**: Apache Maven (Multi-module project)
- **Test Framework**: JUnit 4.x with Spring Test Framework
- **Language**: Java 8
- **Project Type**: OSS-Fuzz compatible with .oss-fuzz/ directory

## Build System

### Maven Configuration

**Root POM**: `pom.xml`
- **GroupId**: `org.geonetwork-opensource`
- **ArtifactId**: `geonetwork`
- **Version**: `4.0.4-SNAPSHOT`
- **Packaging**: Multi-module project (pom)

### Test Plugin Configuration

**Maven Surefire Plugin** (version 3.0.0-M5):
```xml
<configuration>
  <excludedGroups>org.fao.geonet.repository.AbstractSpringDataTest</excludedGroups>
  <argLine>-Dfile.encoding=UTF-8 -Xmx1G -Djava.awt.headless=true</argLine>
  <runOrder>alphabetical</runOrder>
  <forkCount>${system.numCores}</forkCount>
  <redirectTestOutputToFile>true</redirectTestOutputToFile>
  <excludes>
    <exclude>**/*PerformanceTest.java</exclude>
  </excludes>
</configuration>
```

**Key Exclusions**:
- Performance tests: `**/*PerformanceTest.java`
- Abstract test group: `org.fao.geonet.repository.AbstractSpringDataTest`

## Project Modules

The project consists of 28 Maven modules:

### Core Modules (with tests)
1. **common** - Common utilities and shared code
2. **cachingxslt** - XSLT caching utilities
3. **sde** - SDE database support
4. **domain** - Domain entities and JPA repositories
5. **oaipmh** - OAI-PMH protocol support
6. **events** - Event handling system
7. **core** - Core GeoNetwork functionality
8. **listeners** - Event listeners
9. **schemas** - Metadata schema support
10. **csw-server** - CSW server implementation
11. **harvesters** - Metadata harvesting modules
12. **healthmonitor** - Health monitoring
13. **services** - Service layer and REST APIs
14. **wro4j** - Web resource optimization
15. **inspire-atom** - INSPIRE Atom feed support
16. **doi** - Digital Object Identifier support
17. **es** - Elasticsearch integration
18. **workers** - Background worker modules
19. **messaging** - Messaging infrastructure
20. **index** - Search indexing

### Test-Only Modules
21. **schemas-test** - Schema testing utilities
22. **estest** - Elasticsearch testing utilities
23. **integration-test** - BDD/Cucumber integration tests
24. **jmeter** - JMeter performance tests

### Deployment/Release Modules
25. **release** - Release packaging
26. **web-ui** - Angular-based web UI
27. **web** - WAR packaging and deployment
28. **slave** - Slave node configuration

### Documentation
29. **docs** - Project documentation

## Test Structure

### Unit Tests

**Total Count**: 235 test files ending with `*Test.java`
**Total Java Files in Test Directories**: 262 files (includes utilities, mocks, and abstract base classes)

#### Test File Naming Conventions
- Regular tests: `*Test.java` (e.g., `DateUtilTest.java`, `ThesaurusTest.java`)
- Integration tests: `*IntegrationTest.java` (38 files)
- Abstract base tests: `Abstract*Test.java` (17 files)
- Mock objects: `*Mock*.java` (6 files in test directories)

#### Test Directory Structure
Tests follow Maven standard directory structure:
```
<module>/
├── src/
│   ├── main/java/          # Production code
│   └── test/
│       ├── java/           # Test source code
│       └── resources/      # Test resources (XML, properties, etc.)
```

### Key Test Modules and Counts

#### 1. Common Module (`common/src/test/`)
Tests for common utilities:
- `ZipUtilTest.java`
- `DateUtilTest.java`
- `IOTest.java`, `IOMemoryFsTest.java`
- `XmlTest.java`
- `NioPathAwareCatalogResolverTest.java`
- `GeonetHttpRequestFactoryTest.java`
- `PrefixUrlRewriteTest.java`

#### 2. Core Module (`core/src/test/`)
Extensive testing of core functionality:
- **Kernel Tests**: `DataManagerIntegrationTest.java`, `AccessManagerTest.java`, `ThesaurusTest.java`, `SchematronValidatorTest.java`
- **Search Tests**: `KeywordsSearcherTest.java`, `CharToSpaceReaderTest.java`, `TermUriTranslatorTest.java`
- **MEF Export Tests**: `MEFExporterIntegrationTest.java`, `MEFLibIntegrationTest.java`
- **Security Tests**: `GeonetworkAuthenticationProviderIntegrationTest.java`, `LDAPRoleConverterTest.java`, `ShibbolethUserUtilsTest.java`
- **XLink Tests**: `LocalXLinksInMetadataIntegrationTest.java`, `LocalXLinksUpdateDeleteTest.java`
- **Base Classes**: `AbstractCoreIntegrationTest.java`, `AbstractDataManagerIntegrationTest.java`, `AbstractThesaurusBasedTest.java`

#### 3. Domain Module (`domain/src/test/`)
JPA repository and domain entity tests:
- **Entity Tests**: `UserTest.java`, `UserGroupTest.java`, `ISODateTest.java`, `SchematronTest.java`, `HarvestHistoryTest.java`
- **Repository Tests**:
  - `MetadataRepositoryTest.java`
  - `UserRepositoryTest.java`
  - `GroupRepositoryTest.java`
  - `SchematronRepositoryTest.java`
  - `HarvesterSettingRepositoryTest.java`
  - `OperationAllowedRepositoryTest.java`
  - `MetadataStatusRepositoryTest.java`
- **Base Classes**: `BasicAbstractMetadataTest.java`, `AbstractOperationsAllowedTest.java`

#### 4. Services Module (`services/src/test/`)
69 test files covering REST APIs and service layer:
- Organized into subdirectories: `api/`, `guiservices/`, `services/`
- Tests for RESTful web services
- GUI service validation tests

#### 5. CSW Server Module (`csw-server/src/test/`)
CSW protocol implementation tests:
- `CswGetRecords_Test.java`
- `CswGetRecords_SearchOrderIntegrationTest.java`
- `CswTransactionIntegrationTest.java`

#### 6. Harvesters Module (`harvesters/src/test/`)
Tests for metadata harvesting functionality

#### 7. Workers Module (`workers/`)
- `wfsfeature-harvester/src/test/` - WFS feature harvesting tests

### Integration Tests

#### BDD/Cucumber Tests (`integration-test/`)
- **Framework**: Cucumber with Selenium WebDriver
- **Dependencies**:
  - cucumber-java (1.2.5)
  - cucumber-junit (1.2.5)
  - selenium-java (3.5.3)
  - JUnit 4.13.1
- **Feature Files**: 12 Cucumber feature files (`.feature`)
- **Step Definitions**:
  - `RunCukeTest.java` - Test runner
  - `PredefinedStepDefinitions.java`
  - `UserStepDefinitions.java`
  - `Hooks.java` - Test lifecycle hooks
- **Test Support**:
  - `env/BaseTest.java`, `env/Env.java`
  - `methods/ConfigurationMethods.java`
  - `methods/ErrorHandlingMethods.java`
  - `methods/JavascriptHandlingMethods.java`

Example feature files:
- `002.load_samples.feature`
- `030.create_new_user.feature`
- `042.edit_with_another_editor.feature`
- `098.cleanup.feature`
- `099.exit.feature`

#### Integration Test Modules
- **estest** - Elasticsearch integration tests
- **schemas-test** - Schema validation integration tests

### Test Resources

Test resource directories found in 13 modules:
- `workers/wfsfeature-harvester/src/test/resources/`
- `core/src/test/resources/`
- `domain/src/test/resources/`
- `schemas-test/src/test/resources/`
- `services/src/test/resources/`
- `harvesters/src/test/resources/`
- `common/src/test/resources/`
- `csw-server/src/test/resources/`
- `integration-test/src/test/resources/`
- `estest/src/test/resources/`
- `schemas/iso19139/src/test/resources/`
- `schemas/iso19115-3.2018/src/main/test/resources/`
- `wro4j/src/test/resources/`

**Resource Types**:
- XML configuration files (Spring contexts, test data)
- Properties files
- Sample metadata documents
- SLD (Styled Layer Descriptor) files
- Test database schemas
- Cucumber feature files

### Test Base Classes and Utilities

**Abstract Test Base Classes** (41 utility files found):
1. `AbstractCoreIntegrationTest.java` - Base for core integration tests
2. `AbstractDataManagerIntegrationTest.java` - Data manager test base
3. `AbstractThesaurusBasedTest.java` - Thesaurus testing base
4. `AbstractSpringDataTest.java` - Spring Data JPA test base (excluded from runs)
5. `AbstractGeonetworkDataDirectoryTest.java` - Data directory test base
6. `AbstractIntegrationTestWithMockedSingletons.java` - Mocking support
7. `AbstractLanguageSearchOrderIntegrationTest.java` - I18n search tests
8. `AbstractOperationsAllowedTest.java` - Security test base
9. `BasicAbstractMetadataTest.java` - Metadata entity test base
10. `AbstractIOTest.java` - I/O utilities test base

**Test Utilities and Helpers**:
- `GeonetTestFixture.java` - Test fixture setup
- `TestDatabasePopulator.java` - Database test data
- `MockRequestFactoryGeonet.java` - HTTP request mocking
- `GeonetMockServletContext.java` - Servlet context mocking
- `FileSystemPool.java` - Test filesystem management
- `TestThreadPool.java` - Thread pool for testing
- `NullableThesaurusFinder.java` - Test thesaurus finder
- `ForceInitRepositoriesForTestingBean.java` - Repository initialization

**Mock Classes** (6 files):
- `MockService.java`
- `MockCloseableHttpResponse.java`
- `GeonetMockServletContext.java`
- `MockRequestFactoryGeonet.java`

### Performance Tests

**Excluded by Maven Surefire**:
- Pattern: `**/*PerformanceTest.java`
- Module: `jmeter/` contains JMeter performance test scripts

## Test Execution

### Standard Test Command

From the root project directory:
```bash
mvn test
```

This will:
1. Compile all modules
2. Run unit tests in each module
3. Exclude performance tests and abstract test groups
4. Use parallel execution (forkCount based on CPU cores)
5. Redirect test output to files

### Module-Specific Testing

Test individual modules:
```bash
mvn test -pl common
mvn test -pl core
mvn test -pl domain
mvn test -pl services
```

### Build with Tests

The OSS-Fuzz build script uses:
```bash
mvn -DskipTests clean install
```

This **skips all tests** during the fuzzing build process.

### Integration Tests

Cucumber integration tests require a running GeoNetwork instance:
```bash
cd integration-test
mvn test -Dwebdriver-download
```

## Patch Exclude List

### Current Exclusions (from `.aixcc/meta.yaml`)

The current patch exclude list is minimal and C/C++-focused:
```yaml
patch_exclude_list:
- build.sh
- Makefile
- CMakeLists.txt
- configure*
- '*.ac'
- '*.am'
- .gitignore
- .aixcc/**
- '**/*test*.c'
- '**/*test*.cc'
- '**/*test*.cpp'
- '**/*test*.h'
- test/**
- tests/**
- docs/**
- '*.md'
- README*
```

### Comprehensive Java Test Exclusion List

For a **Java Maven project**, the following patterns should be added to exclude all test code:

```yaml
patch_exclude_list:
  # Build and configuration files
  - build.sh
  - Dockerfile
  - .gitignore
  - .aixcc/**
  - '*.md'
  - README*
  - LICENSE*

  # Maven build files (optional - may want to patch)
  - pom.xml
  - .mvn/**

  # Documentation
  - docs/**
  - '**/doc/**'
  - '**/docs/**'

  # Test directories (Maven standard)
  - '**/src/test/**'
  - test/**
  - tests/**

  # Test-only modules
  - integration-test/**
  - schemas-test/**
  - estest/**
  - jmeter/**

  # Test files by naming convention
  - '**/*Test.java'
  - '**/*Tests.java'
  - '**/*TestCase.java'
  - '**/*IntegrationTest.java'
  - '**/*PerformanceTest.java'
  - '**/Test*.java'

  # Test utilities and mocks
  - '**/*Mock*.java'
  - '**/Abstract*Test*.java'
  - '**/*TestFixture*.java'
  - '**/*TestUtil*.java'
  - '**/*TestHelper*.java'
  - '**/*TestBase*.java'

  # Test resources
  - '**/src/test/resources/**'
  - '**/*.feature'

  # Build output directories
  - '**/target/**'
  - '**/build/**
  - '**/out/**
  - '**/bin/**

  # IDE and tooling
  - .idea/**
  - .vscode/**
  - '*.iml'
  - .classpath
  - .project
  - .settings/**

  # Version control
  - .git/**
  - .gitattributes
  - .gitmodules
  - .github/**

  # CI/CD
  - .travis.yml
  - .circleci/**
  - .gitlab-ci.yml
  - Jenkinsfile

  # Code quality tools
  - code_quality/**
  - .checkstyle
  - findbugs-excludes.xml

  # Transifex localization
  - transifex/**
  - transifex-localization-files.json

  # Scripts
  - '*.sh'
  - add-schema.sh
  - update-version.sh
  - updateReleaseVersions.sh
  - updateBranchVersions.sh
  - resetReleaseVersions.sh
```

### Minimal Recommended Exclusion List

If you want a more focused exclusion list that covers the essential test code:

```yaml
patch_exclude_list:
  # Test directories
  - '**/src/test/**'
  - integration-test/**
  - schemas-test/**
  - estest/**
  - jmeter/**

  # Test files
  - '**/*Test.java'
  - '**/*IntegrationTest.java'
  - '**/*Mock*.java'
  - '**/Abstract*Test*.java'

  # Build and infrastructure
  - build.sh
  - Dockerfile
  - .aixcc/**
  - '**/target/**'
  - pom.xml

  # Documentation
  - docs/**
  - '*.md'
  - README*
```

## Test Dependencies

Key test frameworks and libraries:

### Unit Testing
- **JUnit 4.13.1** - Test framework
- **Spring Test** - Spring integration testing
- **Mockito** - Mocking framework (implied by test utilities)
- **H2 Database** - In-memory database for tests (from domain tests)

### Integration Testing
- **Cucumber 1.2.5** - BDD framework
- **Selenium WebDriver 3.5.3** - Browser automation
- **PhantomJS Driver 1.4.3** - Headless browser testing

### Other Test Libraries
- **Hamcrest** - Assertion matchers (JUnit dependency)
- **SLF4J** - Logging for tests

## Test Coverage Areas

### 1. Utility and Common Code
- XML processing and validation
- Date/time utilities
- File I/O operations
- HTTP request handling
- URL parsing and rewriting

### 2. Domain and Persistence
- JPA entity validation
- Repository operations (CRUD)
- Database queries and constraints
- Transaction management
- Domain object relationships

### 3. Core Business Logic
- Metadata management (DataManager)
- Access control and permissions (AccessManager)
- Schema validation (Schematron)
- Thesaurus and keyword management
- MEF import/export
- Local XLinks processing

### 4. Search and Indexing
- Keyword search
- Multilingual search ordering
- Term URI translation
- Query building

### 5. Security
- Authentication providers
- LDAP role conversion
- Shibboleth integration
- User session management

### 6. Services and APIs
- REST API endpoints (69 test files)
- CSW protocol operations
- Service dispatching
- GUI services

### 7. Harvesting
- Metadata harvesting
- WFS feature harvesting
- Harvester configuration

### 8. Integration Scenarios
- End-to-end user workflows (Cucumber)
- Sample data loading
- User creation and management
- Editing workflows

## Notes and Observations

1. **Test Philosophy**: Heavy use of Spring integration tests with actual database and service context
2. **Test Isolation**: Uses H2 in-memory database and temporary file systems for isolation
3. **Mocking Strategy**: Limited mocking, prefers integration testing over unit testing
4. **Parallel Execution**: Configured for parallel test execution based on CPU cores
5. **Test Organization**: Well-structured with abstract base classes for common test setup
6. **Coverage**: Comprehensive coverage of domain, core, and service layers
7. **BDD Testing**: Separate integration-test module for end-to-end scenarios
8. **Test Data**: Extensive use of test resources (XML, properties, sample data)

## Recommendations for CRS Patch Generation

When generating patches for this project:

1. **Always exclude test code** - Use the comprehensive exclusion list above
2. **Be cautious with pom.xml** - Changes may affect build, consider excluding
3. **Focus on production code** - Only patch code in `src/main/java/` directories
4. **Preserve API contracts** - Many tests validate API behavior, don't break contracts
5. **Consider Spring configuration** - Test failures may indicate Spring bean issues
6. **Validate schema changes** - Schema validation tests are extensive
7. **Check security implications** - Security tests validate access control logic
8. **Test harness alignment** - Ensure patches don't break fuzzing harness integration

## Summary Statistics

- **Total Modules**: 28
- **Modules with Tests**: ~20
- **Test Files (*Test.java)**: 235
- **Integration Test Files**: 38
- **Abstract Test Base Classes**: 17
- **Mock/Utility Files**: 47
- **Cucumber Feature Files**: 12
- **Test Resource Directories**: 13
- **Build System**: Maven 3.x
- **Test Framework**: JUnit 4.x + Spring Test
- **Java Version**: 1.8
- **Test Execution**: Parallel (CPU-based forkCount)
- **OSS-Fuzz Build**: Tests skipped (`-DskipTests`)
