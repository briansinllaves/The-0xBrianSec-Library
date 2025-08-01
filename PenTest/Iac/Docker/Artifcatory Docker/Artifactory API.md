## Artifactory API

### List All Repositories
```bash
curl -u $user:$token https://art-w.test.com/artifactory/api/repositories > repositories
```

#### In PowerShell
```powershell
Invoke-RestMethod -Uri 'https://art-w.test.com/artifactory/api/repositories' -Method GET -Headers @{Authorization = "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${user}:${token}")))"}
```

## AQL Queries
```bash
curl -X POST -u $user:$token 'https://art-w.test.com/artifactory/api/search/aql' -T aql.query
```

## AQL Examples

### List All Images
```aql
items.find({ "repo": { "$eq": "g00076-EXAMPLE-REPLACE-ME-docker-local" }, "[@docker.repone]": { "$eq": "*" } }).include("ne", "repo", "path", "size")
```

### List 10 Biggest Images
```aql
items.find({ "repo": "g00076-EXAMPLE-REPLACE-ME-docker-local" }).include("ne", "repo", "path", "size").sort({ "$desc": ["size"] }).limit(10)
```

### List 10 Most Recent Images
```aql
items.find({ "repo": "g00076-EXAMPLE-REPLACE-ME-docker-local" }).sort({ "$desc": ["created"] }).limit(10)
```

