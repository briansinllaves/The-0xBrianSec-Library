Commands and tasks related to managing Docker images with Artifactory that administrators might find useful. 

These include more advanced querying, cleaning up old images, managing access tokens, and using Artifactory's REST API for various management tasks.

### Additional Artifactory Commands for Docker Management

#### List All Builds for an Artifactory Project
```bash
curl -u $user:$token 'https://art-w.test.com/artifactory/api/build?project=w035'
```

#### List All Build Numbers for a Specific Build
```bash
curl -u $user:$token 'https://art-w.test.com/artifactory/api/build/DocumentLibrary%20-%20Docker%20Build%20&%20Deploy?project=w06665'
```

#### Get Build Info for a Specific Build Number
```bash
curl -u $user:$token 'https://art-w.test.com/artifactory/api/build/DocumentLibrary%20-%20Docker%20Build%20&%20Deploy/201.3?project=w06665'
```

#### Delete an Image
```bash
curl -u $user:$token -X DELETE 'https://art-w.test.com/artifactory/docker-local/myimage:latest'
```

#### List Tags for a Specific Repository
```bash
curl -u $user:$token 'https://art-w.test.com/artifactory/api/docker/my-repo/v2/tags/list'
```

#### Clean Up Old Docker Images
```bash
curl -u $user:$token -X POST 'https://art-w.test.com/artifactory/api/cleanup/docker?repoKey=my-repo&maxDays=30'
```

#### Promote Docker Image to a Production Repository
```bash
curl -u $user:$token -X POST 'https://art-w.test.com/artifactory/api/docker/promote' -d '{"targetRepo" : "my-production-repo", "dockerRepository" : "my-repo/myimage", "tag" : "latest"}'
```

#### Create a Docker Repository
```bash
curl -u $user:$token -X PUT 'https://art-w.test.com/artifactory/api/repositories/my-new-repo' -d '
{
  "key": "my-new-repo",
  "rclass": "local",
  "packageType": "docker"
}'
```

#### Update Repository Configuration
```bash
curl -u $user:$token -X POST 'https://art-w.test.com/artifactory/api/repositories/my-repo' -d '
{
  "key": "my-repo",
  "description": "Updated description",
  "notes": "Updated notes"
}'
```

#### Fetch Access Token
```bash
curl -u $user:$token -X POST 'https://art-w.test.com/artifactory/api/security/token' -d '
{
  "userne": "myuser",
  "scope": "member-of-groups:readers",
  "expires_in": 3600
}'
```

#### Revoke Access Token
```bash
curl -u $user:$token -X DELETE 'https://art-w.test.com/artifactory/api/security/token/revoke'
```

