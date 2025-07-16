### List All Docker Builds for Artifactory Project
```bash
curl -u user:token 'https://artifacts-west.test.com/artifactory/api/build?project=w035'
```

### List All Build Numbers for a Build
```bash
curl -u user:token 'https://artifacts-west.test.com/artifactory/api/build/DocumentLibrary%20-%20Docker%20Build%20&%20Deploy?project=w06665'
```

### List Build Info for a Specific Build Number
```bash
curl -u user:token 'https://artifacts-west.test.com/artifactory/api/build/DocumentLibrary%20-%20Docker%20Build%20&%20Deploy/201.3?project=w06665'
```