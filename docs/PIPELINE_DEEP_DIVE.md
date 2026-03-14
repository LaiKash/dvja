# DevSecOps Pipeline: Comprehensive Analysis

**Date:** 2026-03-11
**Application:** DVJA (Damn Vulnerable Java Application)
**Stack:** Java 8, Struts2, Spring, Hibernate, MySQL, Docker

---

## Table of Contents

1. [Tools Used](#1-tools-used)
2. [Pipeline Architecture](#2-pipeline-architecture)
3. [Job-by-Job Breakdown](#3-job-by-job-breakdown)
4. [Issue Management Strategy](#4-issue-management-strategy)

---

## 1. Tools Used

| Tool | Category | Purpose | Output |
|------|----------|---------|--------|
| **GitHub Actions** | CI/CD Platform | Orchestrates the entire pipeline: triggers on push/PR, runs jobs in parallel, manages artifacts | Workflow runs, logs |
| **Maven** | Build | Compiles the Java application and packages it as a WAR file | `target/*.war` |
| **Docker** | Containerization | Builds and pushes the application image to Docker Hub | Tagged container image |
| **Gitleaks** | Secrets Detection | Scans files for provider-specific tokens (AWS keys, GitHub tokens, private keys, etc.) using ~150 built-in regex rules | SARIF |
| **detect-secrets** (Yelp) | Secrets Detection | Complements Gitleaks, catches generic hardcoded passwords in config files via keyword matching and entropy analysis | JSON |
| **CodeQL** | SAST | Analyzes Java source code for exploitable patterns: SQL injection, command injection, log injection, sensitive data exposure | SARIF (uploaded to GitHub Security tab) |
| **Trivy** (filesystem mode) | SCA | Scans `pom.xml` for known CVEs in third-party dependencies | JSON + SARIF |
| **Trivy** (image mode) | Container Security | Scans the built Docker image for OS and library vulnerabilities in the deployed artifact | JSON + SARIF |

**Why these tools?** All are open-source, free for public repositories, and produce standard output formats (SARIF/JSON). They cover four complementary layers of the security stack, secrets, code, dependencies, and runtime image, without requiring paid licenses or external services.

---

## 2. Pipeline Architecture

### Execution Flow

```
                    ┌─────────────┐
                    │   JOB 1     │
                    │   Build     │
                    │  (Maven)    │
                    └──────┬──────┘
                           │
              ┌────────────┼─────────────┬───────────────┐
              │            │             │               │
              ▼            ▼             ▼               ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐  ┌──────────────┐
        │  JOB 2   │ │  JOB 3   │ │  JOB 4   │  │    JOB 5     │
        │ Secrets  │ │   SAST   │ │   SCA    │  │ Docker Build │
        │(Gitleaks)│ │ (CodeQL) │ │ (Trivy)  │  │   & Push     │
        └────┬─────┘ └────┬─────┘ └────┬─────┘  └──────┬───────┘
             │            │            │                │
             │            │            │                ▼
             │            │            │         ┌──────────────┐
             │            │            │         │    JOB 6     │
             │            │            │         │  Container   │
             │            │            │         │   Security   │
             │            │            │         │   (Trivy)    │
             │            │            │         └──────┬───────┘
             │            │            │                │
             └────────────┴────────────┴────────────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │     JOB 7       │
                          │ Create GitHub   │
                          │    Issues       │
                          └─────────────────┘
```

### Parallelism

Jobs 2, 3, 4, and 5 run **in parallel** after the build completes. This is important for pipeline speed, we can parallelice the jobs that don't depend on each other. The only obvious sequential dependency is:

- Job 5 (Docker Build) **must finish before** Job 6 (Container Scan) can start
- Job 7 (Issue Creation) waits for **all** scanning jobs to finish

### Triggers

```yaml
on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
```

The pipeline runs on:
- **Push to main/master:** scans the code that was just merged. 
- **Pull request to main/master:** scans the proposed changes before merge.

The instructions said to do it just in main, but the original project uses master, so I included it in both.

---

## 3. Job-by-Job Breakdown

### Job 1: Build Application

```yaml
build:
  steps:
    - Checkout source
    - Set up JDK 8
    - Cache Maven packages
    - Build with Maven (skip tests)
    - Upload WAR artifact
```

Compiles the Java source code into a WAR (Web Application Archive) file, the deployable artifact for Java web applications.

**Key decisions:**
- **`-DskipTests`:** Skips unit tests for build speed as it is a security focused pipeline
- **Maven cache:** Uses `actions/cache@v4` keyed on `pom.xml` hash. Avoids re-downloading all dependencies on every run (saves some time).
- **Artifact upload:** The WAR file is saved as a GitHub Actions artifact so downstream jobs (Docker build) can use it without rebuilding.

The build happens once, and the artifact is shared. This follows the "build once, deploy everywhere" principle. The same WAR gets scanned and containerized, so what it is analysed is what is shipped.

---

### Job 2: Secrets Detection (Gitleaks + detect-secrets)

```yaml
secrets-scan:
  needs: build
  continue-on-error: true
  steps:
    - Run Gitleaks (full file scan, --no-git)
    - Run detect-secrets (keyword + entropy analysis)
    - Upload Gitleaks report (SARIF)
    - Upload detect-secrets report (JSON)
```

Scans the repository for accidentally committed secrets: API keys, passwords, tokens, private keys. For this specific project the pipeline uses two complementary tools.

**Why two scanners?** No single open-source secrets scanner covers all secret types well and this application has a database and some configuration files that are indeed vulnerable and we want to scan.. After testing several tools the conclusion is:

| Tool | Provider tokens (AWS, GitHub, etc.) | Generic `password=value` in configs | Custom rules needed? |
|------|-------------------------------------|-------------------------------------|----------------------|
| **Gitleaks** | Excellent (~150 rules) | No | Yes (custom `.toml`) |
| **detect-secrets** | Limited | Excellent (KeywordDetector + entropy) | No |
| Combined | Excellent | Excellent | **No** |

**How Gitleaks works:**
1. ~150 built-in regex rules targeting specific secret formats (AWS access keys with `AKIA` prefix, GitHub tokens with `ghp_`, Slack webhooks, RSA private keys, etc.)
2. Scans files on disk in `--no-git` mode. This is intended for this build, bypasses git history, catches any secret currently present. 
3. Outputs SARIF format

**How detect-secrets works:**
1. **KeywordDetector**: flags lines where keywords like `password`, `secret`, `token`, `api_key` appear in assignment context (e.g., `mysql.password=...`, `MYSQL_PASSWORD: ...`)
2. **HexHighEntropyString / Base64HighEntropyString**: flags values with high randomness that look like real credentials
3. Additional plugins for AWS keys, GitHub tokens, JWT, private keys, etc.
4. Outputs JSON with file paths, line numbers, and finding types

**Deduplication:** Both scanners' findings are merged in the issue creation step, deduplicated by `file:line` to avoid reporting the same secret twice, as they can solapate.

**Scanning strategy:**
- **Default (push/PR):** Gitleaks `--no-git` + detect-secrets scan **all files** on disk. The default behaviour would be just to scan the last commit, which we want to avoid in this specific pipeline (scanning a fork of a project). Fast and catches any secret currently in the codebase.
- **Full git-history audit (not applied):** Run `gitleaks detect --log-opts=--all` via `workflow_dispatch` to find secrets that were committed and later deleted (still in history, still need rotation). This strategy was not applied in this case as it is a fork. My professional recommendation is to have a manual action that would perform this audit and that would run onces per month. This would be interesting for another strategy when the pipeline is already matured.

**`continue-on-error: true`:**  Secrets detection runs in **monitoring mode**. Even if secrets are found, the pipeline continues. This is a deliberate choice for early DevSecOps adoption: blocking on every finding creates friction. Once the backlog is cleared, switch to `continue-on-error: false` (blocking mode) would be a better security approach, but it should be handled per team, project and process individially.

---

### Job 3: SAST: CodeQL

```yaml
codeql-sast:
  needs: build
  permissions:
    security-events: write
  steps:
    - Initialize CodeQL
    - Set up JDK 8
    - Build for CodeQL
    - Index XML and properties files
    - Perform CodeQL Analysis
    - Upload CodeQL SARIF
```

Static Application Security Testing (SAST): self explanatory, analyzes the compiled Java bytecode for vulnerability patterns like SQL injection, command injection, XSS, and insecure data handling.

**The `security-and-quality` query suite:**
This is CodeQL's extended query set. The default `security-extended` suite focuses purely on security. `security-and-quality` adds code quality rules that have security implications (like log injection).

**XML configuration file indexing:**
```yaml
- name: Index XML configuration files
  run: |
    codeql database index-files \
      --language xml \
      --include-extension .xml \
      -- ${{ runner.temp }}/codeql_databases/java
```

By default, CodeQL's Java extractor only captures `.java` and `.class` files. Configuration files like `struts.xml` are invisible to queries unless explicitly indexed. This step adds `.xml` files to the database, enabling detection of `struts.devMode=true` (security misconfiguration missed otherwise).

**Permissions:**
`security-events: write` is required because CodeQL uploads results to GitHub's Security tab (Code Scanning alerts), not just as a workflow artifact.

---

### Job 4: SCA, Trivy Dependencies

```yaml
trivy-sca:
  continue-on-error: true
  steps:
    - Checkout source
    - Run Trivy on filesystem (JSON)
    - Produce SARIF for GitHub Security tab
    - Upload Trivy SCA SARIF
    - Upload Trivy SCA JSON
```

Software Composition Analysis (SCA): identifies known vulnerabilities (CVEs) in third-party dependencies declared in `pom.xml`.

**Why does Trivy run twice?** The `aquasecurity/trivy-action` only supports one output format per invocation. The first run produces JSON (consumed by the issue creation script), the second produces SARIF (uploaded to GitHub's Security tab). Both filter to CRITICAL and HIGH only.

---

### Job 5: Build & Push Docker Image

```yaml
docker-build-push:
  needs: build
  steps:
    - Download WAR artifact
    - Remove target from .dockerignore
    - Log in to Docker Hub
    - Set up Docker Buildx
    - Extract metadata (tags & labels)
    - Build and push image
```

Packages the application into a Docker container image and pushes it to Docker Hub.

**Image tagging strategy:**
```yaml
tags: |
  type=sha,prefix=sha-          # sha-8c0bd80 (short commit SHA)
  type=ref,event=branch          # main (branch name)
  type=raw,value=${{ github.sha }}  # full SHA as exact reference
  type=raw,value=latest,enable=...  # 'latest' only on main/master
```

This produces multiple tags for the same image:
- **SHA-based tags** (`sha-8c0bd80`, full SHA): immutable, uniquely identify a build. Used for traceability: "which exact code is running in production?"
- **Branch tag** (`main`): mutable, always points to the latest build from that branch
- **`latest`**: conventional tag for the most recent stable build. Only applied on main/master.

Using the full commit SHA as the `IMAGE_TAG` environment variable ensures that the container scan (Job 6) scans the exact image that was just built, not a stale `latest` tag.

**Buildx and layer caching:**
```yaml
cache-from: type=gha
cache-to: type=gha,mode=max
```
This uses GitHub Actions built-in cache for Docker layers. On subsequent builds, unchanged layers (like `apt-get install`) are cached, significantly reducing build time. `mode=max` caches all layers, including intermediate ones.

**The `.dockerignore` workaround:**
```yaml
- name: Remove target from .dockerignore
  run: sed -i '/^target/d' .dockerignore
```
The `.dockerignore` excludes `target/` (where Maven puts build output), but the Dockerfile needs the WAR from `target/`. Since the WAR was built in Job 1 and downloaded as an artifact, this step removes the ignore rule so Docker can see it.

---

### Job 6: Container Security, Trivy Image Scan

```yaml
trivy-container:
  needs: docker-build-push
  steps:
    - Log in to Docker Hub
    - Run Trivy container scan (JSON)
    - Run Trivy container scan (SARIF)
    - Upload container SARIF
    - Upload container scan JSON
```

Scans the built Docker image for vulnerabilities in both OS packages and bundled libraries.

**`vuln-type: 'os,library'`:**

| Value | What it scans | Example findings |
|-------|--------------|-----------------|
| `os` | Only OS packages (apt, dpkg, rpm) | `libssl3` has CVE-2024-XXXX |
| `library` | Only language packages (JARs, npm, etc.) | `struts2-core-2.3.30.jar` has CVE-2017-5638 |

**Why scan the container if SCA already scans `pom.xml`?**

Defense-in-depth. The SCA step and the container scan serve different purposes:

For example, iff the Dockerfile copies an additional JAR (`COPY lib/legacy.jar /app/lib/`) that isn't in `pom.xml`, only the container scan would find it. If a test-scope dependency in `pom.xml` isn't packaged into the WAR, SCA would flag it but the container scan wouldn't.

There can be some vulnerabilities in the container itself that could be exploited (either by their own or through an exploit chain, as it is the case)

---

### Job 7: Create Security Issues

```yaml
create-security-issues:
  needs: [ secrets-scan, codeql-sast, trivy-sca, trivy-container ]
  if: always()
  permissions:
    issues: write
  steps:
    - Download all report artifacts
    - Create categorized security issues
```

Aggregates findings from all four scanners, deduplicates them against existing open issues, and creates well-formatted GitHub Issues with structured metadata. This is to create the issues for developers. Without it, they would stay in the security tab.

**How findings are categorized:**

As this is a *very* vulnerable project, the ammount of created issues can be huge. This can increase friction and the issues could just get ignored.
The followed strategy is to categorise each vulnerability and create "packs" to push just one issue per "pack". This also creates more meaningful issues that will increase how developers solve each one, increasing ownsership.

| Scanner | Issue prefix | Labels | Grouping strategy |
|---------|-------------|--------|-------------------|
| Trivy SCA | `[DEPENDENCY]` | `security`, `dependency`, severity | One issue per vulnerable package (groups all CVEs) |
| Trivy Image | `[CONTAINER]` | `security`, `container`, severity | One issue per vulnerable package |
| CodeQL | `[CODE]` | `security`, `code`, severity | One issue per rule (groups all locations) |
| Gitleaks + detect-secrets | `[SECRET]` | `security`, `secret`, `critical` | One combined issue, deduplicated by file:line |

**Deduplication strategy:**
Javascript was used for the pipeline scripts.

```javascript
const existingTitles = new Set(allOpen.map(i => i.title));
// ...
if (existingTitles.has(issue.title)) { skipped++; continue; }
```
Title-based deduplication: if an open issue with the same title already exists, skip it. This prevents duplicate issues on repeated pipeline runs. When a vulnerability is fixed and the issue is closed, it won't be re-created unless the vulnerability reappears.

**Rate limiting protection:**
```javascript
await new Promise(r => setTimeout(r, 1000));  // 1-second delay between issues
if (err.status === 403 && err.message.includes('rate limit')) break;
```
GitHub's API has rate limits. The script adds a 1-second delay between issue creation and stops gracefully if rate-limited.

**Severity filtering in CodeQL:**
```javascript
const secSev = parseFloat(rule.properties?.['security-severity'] || '0');
if (secSev >= 9.0) severity = 'CRITICAL';
else if (secSev >= 7.0 || result.level === 'error') severity = 'HIGH';
else continue;  // skip MEDIUM and LOW
```
Only HIGH and CRITICAL findings become issues. This threshold aligns with industry practice: MEDIUM findings are still visible in the GitHub Security tab but don't create issue noise. The `security-severity` field comes from CodeQL's rule metadata and maps roughly to CVSS scores.

---

## 4. Issue Management Strategy

### Issue Lifecycle

```
Scanner finds vulnerability
        │
        ▼
Is there an open issue with same title? ──Yes──► Skip (deduplicated)
        │ No
        ▼
Create GitHub Issue with labels
        │
        ▼
Developer triages (true positive? false positive?)
        │
    ┌───┴───┐
    │       │
    ▼       ▼
  Fix it   Close as
  in code  "won't fix"
    │       (with justification)
    ▼
  Close issue
    │
    ▼
Next pipeline run: issue stays closed
(unless vulnerability reappears with different title)
```

### Areas for improvement

- **No DAST**: The pipeline only performs static analysis. Adding OWASP ZAP against the running container would catch runtime vulnerabilities like XSS, CSRF, IDOR, and auth bypass that static tools miss.
- **No blocking gate**: All scans use `continue-on-error: true`, so findings never block a merge. Once the backlog is cleared, set `exit-code: '1'` for CRITICAL severity and remove `continue-on-error` to enforce gates.
- **No SLA tracking**: Issues are created but not time-tracked. Best practice is to enforce fix SLAs: CRITICAL = 7 days, HIGH = 30 days.
- **No auto-close**: Fixed vulnerabilities stay open as issues. A job that closes issues when the vulnerability no longer appears would reduce manual triage.
- **No IaC scanning**: The Dockerfile is not scanned for misconfigurations. Adding `trivy config .` or Hadolint would catch best-practice violations (running as root, no health check, etc.).
- **Pinned action versions**: `aquasecurity/trivy-action@master` means the action code can change without notice. Pinning to a version tag (`@0.28.0`) or commit SHA prevents supply chain attacks via compromised actions.


