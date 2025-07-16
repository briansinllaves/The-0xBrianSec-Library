# Pentesting Note: Identifying Sensitive Keys in Codebases

## Objective
Discover and analyze sensitive keys and information in codebases.

## Steps

### 1. Fuzz Directory for .git
Identify if a `.git` directory is present in the target web application's directory structure:

```sh
ffuf -u http://<target_url>/FUZZ -w /path/to/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .git
```

### 2. Check for .git and .git/config
If the `.git` directory is found, check for the presence of the `.git/config` file:

```sh
curl -s http://<target_url>/.git/config
```

### 3. Use GitDumper to Download the Git Repository Locally
If the `.git` directory is accessible, use GitDumper to clone the repository locally:

```sh
python3 gitdumper.py http://<target_url>/.git/ /path/to/local/repo
```

- **GitDumper**: A tool to download the complete contents of a git repository from a website.
  - [GitDumper GitHub Repository](https://github.com/internetwache/GitTools/tree/master/Dumper)

### 4. Perform Analysis with TruffleHog
Analyze the downloaded repository for sensitive information using TruffleHog:

```sh
trufflehog /path/to/local/repo
```

- **TruffleHog**: A tool that searches through git repositories for high entropy strings and secrets, digging deep into commit history.

### Mitigation Tips
- **Restrict Access**: Ensure that the `.git` directory and other sensitive files are not accessible via the web.
- **Regular Audits**: Perform regular audits of codebases to identify and remove sensitive information.
- **Use Environment Variables**: Store sensitive keys and information in environment variables rather than hardcoding them in the source code.
- **Implement Access Controls**: Apply strict access controls to source code repositories to prevent unauthorized access.
