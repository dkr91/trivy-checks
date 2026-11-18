Collection of Docker checks

## Checks implemented in Trivy

Some checks cannot be written in Rego because they need data that is not part of a Dockerfile.
They are implemented in Trivy itself, and their IDs are reserved here so that no Rego check reuses them.

| ID      | Title                                                         | Severity | Implementation |
|---------|---------------------------------------------------------------|----------|----------------|
| DS-0032 | setuid and setgid permissions should be removed in the image | HIGH     | Trivy `pkg/scan/local/fileperm.go`, runs with `--image-config-scanners misconfig` and in the `docker-cis-1.6.0` compliance report (control 4.8) |

### DS-0032

Files with the setuid or setgid bit run with the privileges of their owner or group.
In a container image they can be abused for privilege escalation.

Trivy records the mode of the regular files in every image layer and evaluates the merged filesystem,
so a file whose bits are removed in an upper layer (or that is deleted there) is not reported.

Remediation, e.g.:

```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true
```

References:
- https://www.cisecurity.org/benchmark/docker
