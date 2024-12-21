# ShellCheck SARIF Analysis Action

A GitHub Action that generates SARIF analysis results by running ShellCheck on shell scripts
in your repository.

## Overview

This action utilizes ShellCheck (a third-party static analysis tool) to analyze shell scripts
and generates results in SARIF format. The SARIF output integrates with GitHub Code Scanning
to help track shell script quality and potential security issues.

## Features

- 🔍 Leverages ShellCheck for shell script analysis
- 📊 Generates SARIF format output for GitHub Code Scanning
- 🎯 Configurable file matching patterns
- ⚡ Supports multiple shell dialects (Bash, POSIX, Dash, KSH, BusyBox)
- 🔒 Built-in integration with GitHub Security features

## Dependencies

This action depends on:
- [ShellCheck](https://github.com/koalaman/shellcheck) - A static analysis tool for shell scripts
- Python 3.13 (automatically set up by the action)
- SARIF tooling (automatically installed by the action)

## Usage

Add the following to your GitHub Actions workflow:

```yaml
- name: Run ShellCheck Analysis
  uses: reactive-firewall/shellcheck-scan@v1
  with:
    # Optional: Specify paths to scan (defaults to git-tracked shell scripts)
    path: 'scripts/'
    
    # Optional: Custom glob pattern for matching files
    match: '**/*.{sh,bash,ksh}'
    
    # Optional: Set minimum severity level (style, info, warning, error)
    severity: 'warning'
    
    # Optional: Specify shell dialect (bash, sh, dash, ksh, busybox)
    shell-format: 'bash'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `path` | File or directory to scan | No | Auto-detected |
| `match` | Glob pattern for matching files | No | `**/*.{bash,sh,command}` |
| `severity` | Minimum severity level | No | `style` |
| `shell-format` | Shell dialect to use | No | `AUTOMATIC` |
| `publish-artifacts` | Upload results as artifacts | No | `true` |

## Requirements

This action requires:
- GitHub Actions
- Required permissions:
  - `security-events: write` (for uploading SARIF results)
  - `contents: read` (for scanning repository contents)

## Examples

### Basic Usage

```yaml
name: ShellCheck Analysis

on: [push, pull_request]

jobs:
  shellcheck:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: reactive-firewall/shellcheck-scan@v1
```

### Custom Configuration

```yaml
- uses: reactive-firewall/shellcheck-scan@v1
  with:
    path: 'scripts/'
    severity: 'warning'
    shell-format: 'bash'
    match: '**/*.bash'
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE)
file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any problems, please file an issue along with a detailed description.

---
Last Updated: 2024-12-21
