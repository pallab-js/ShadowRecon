# Security Policy

## Supported Versions

We actively maintain the latest release version. Older versions may not receive security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public issue.

Instead, please email security concerns to the project maintainers or open a private security advisory on GitHub.

### What to Report

- Critical vulnerabilities that could lead to:
  - Remote code execution
  - Privilege escalation
  - Information disclosure
  - Denial of service

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity, typically 30-90 days

## Security Best Practices

When using ShadowRecon:

1. **Only scan authorized targets** - Unauthorized scanning is illegal
2. **Run with minimal privileges** - Use connect scans when possible
3. **Review scan results carefully** - Validate findings independently
4. **Keep the tool updated** - Pull latest changes regularly
5. **Use appropriate timing** - Don't overwhelm target systems

## Known Limitations

- Raw socket operations require elevated privileges
- Some OS fingerprinting features are experimental
- UDP scanning has limitations without ICMP responses

## Responsible Disclosure

We appreciate responsible disclosure of security issues. We will:

- Credit you for the discovery (if desired)
- Work with you to develop a fix
- Release a coordinated security advisory

Thank you for helping keep ShadowRecon secure!
