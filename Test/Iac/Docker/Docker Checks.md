#### Pull Repositories
```bash
curl -u jyo120:A https://artifacts-west.test.com/artifactory/api/repositories > repositories
```

#### Pull Top 10 Largest Images
```bash
curl -X POST -u jy120:AKCp8pQ 'https://artifacts-west.test.com/artifactory/api/search/aql' -T aql
```

#### Docker Login and Pull Images

**Login and Pull Image from Artifacts West**
```bash
docker login -u jyo10 -p AKCpG g076-test-zlop1-gaslamps-ccc-docker-local.artifacts-west.test.com
docker pull g00076-test-zlop1-gaslamps-ccc-docker-local.artifacts-west.test.com/ccc4.0revb:4.0.0revb
```

**Login and Pull Image from Azure Container Registry**
```bash
sudo docker login -u gaslampsCCC -p "ifNtu55BJ...." gaslampsccc.azurecr.io
sudo docker pull gaslampsccc.azurecr.io/ccc-postgres-image-2:ccc-postgres
```

#### List Docker Images in Azure Container Registry
```bash
curl -L --user gaslampsCCC:"ifNtuHoMV2....." gaslampsccc.azurecr.io/v2/_catalog
```

**Pull Latest Image from Artifacts West**
```bash
sudo docker pull g076-test-zlop1-gaslamps-ccc-docker-local.artifacts-west.test.com/test:latest
```
