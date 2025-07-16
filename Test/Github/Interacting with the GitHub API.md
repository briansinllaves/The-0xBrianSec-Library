# Pentesting Note: Interacting with the GitHub API

## Objective
Use the GitHub CLI (`gh`) to interact with the GitHub API and retrieve information about organizations and repositories.

## Commands

### 1. Retrieve Organizations for Authenticated User
This command retrieves the organizations that the authenticated user is a member of:

```sh
gh api --header 'Accept: application/vnd.github+json' --method GET /user/orgs/
```

### 2. Retrieve Repositories of a Specified Organization
This command retrieves the repositories of a specified organization. Replace `$org` with the ne of the organization:

```sh
gh api --header 'Accept: application/vnd.github+json' --method GET /orgs/$org/repos
```

## Explanation
- **`gh api`**: The GitHub CLI command to make API requests.
- **`--header 'Accept: application/vnd.github+json'`**: Sets the Accept header to request a JSON response in GitHub's API v3 format.
- **`--method GET`**: Specifies the HTTP method to use for the request.
- **`/user/orgs/`**: Endpoint to retrieve the organizations the authenticated user belongs to.
- **`/orgs/$org/repos`**: Endpoint to retrieve repositories for a specific organization, where `$org` is the organization ne.

## Usage Example
- **Retrieve Organizations**:
  ```sh
  gh api --header 'Accept: application/vnd.github+json' --method GET /user/orgs/
  ```

- **Retrieve Repositories for an Organization**:
  ```sh
  org="example-org"
  gh api --header 'Accept: application/vnd.github+json' --method GET /orgs/$org/repos
  ```

By using these GitHub CLI commands, you can effectively retrieve information about organizations and repositories, aiding in penetration testing and security assessments.