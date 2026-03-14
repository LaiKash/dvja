# DevSecOps Pipeline — Comprehensive Analysis

**Date:** 2026-03-11
**Application:** DVJA (Damn Vulnerable Java Application)
**Stack:** Java 8, Struts2, Spring, Hibernate, MySQL, Docker

---

## Table of Contents

1. [What is DevSecOps?](#1-what-is-devsecops)
2. [Pipeline Architecture](#2-pipeline-architecture)
3. [Job-by-Job Breakdown](#3-job-by-job-breakdown)
4. [Security Testing Taxonomy](#4-security-testing-taxonomy)
5. [Report Format: SARIF](#5-report-format-sarif)
6. [Issue Management Strategy](#6-issue-management-strategy)
7. [Best Practices Comparison](#7-best-practices-comparison)
8. [Known Limitations and Trade-offs](#8-known-limitations-and-trade-offs)
9. [What Each Tool Can and Cannot Find](#9-what-each-tool-can-and-cannot-find)

---

## 1. What is DevSecOps?

Traditional software development treats security as a gate at the end — a penetration test before release. DevSecOps shifts security **left** into every phase of the development lifecycle:

```
Traditional:   Code → Build → Test → ............... → Security Audit → Deploy
DevSecOps:     Code → [Secrets] → Build → [SAST] → [SCA] → [Container Scan] → Deploy
                 ↑                   ↑        ↑         ↑           ↑
         Gitleaks +          CodeQL    Trivy SCA  Trivy Image   (DAST would go here)
         detect-secrets
```

The goal is **fast feedback** — a developer sees a SQL injection finding in the pull request, not three months later in a pentest report. The pipeline automates what would otherwise require manual security reviews.

### The "Sec" in DevSecOps

Each security tool in the pipeline addresses a different attack surface:

| Tool | What it answers | Analogy |
|------|----------------|---------|
| **Gitleaks + detect-secrets** | "Did someone commit a password?" | Checking your pockets before leaving the house |
| **CodeQL** | "Does my code have exploitable patterns?" | A code reviewer who never gets tired |
| **Trivy SCA** | "Are my dependencies vulnerable?" | Checking if your building materials have recalls |
| **Trivy Container** | "Is the deployed artifact actually safe?" | Inspecting the finished building, not just the blueprints |

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

Jobs 2, 3, 4, and 5 run **in parallel** after the build completes. This is important for pipeline speed — security scanning doesn't have to be sequential. The only sequential dependency is:

- Job 5 (Docker Build) **must finish before** Job 6 (Container Scan) can start — you can't scan an image that doesn't exist yet
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
- **Push to main/master** — scans the code that was just merged
- **Pull request to main/master** — scans the proposed changes before merge

This means security issues are surfaced at two key moments: when reviewing code (PR) and after merging (push). The PR trigger is the "shift-left" gate — catching issues before they reach the main branch.

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

**What it does:** Compiles the Java source code into a WAR (Web Application Archive) file, the deployable artifact for Java web applications.

**Key decisions:**
- **`-DskipTests`** — Skips unit tests for build speed. In a real production pipeline, you'd typically run tests here. For a security-focused pipeline, this is acceptable since the security tools do their own analysis.
- **Maven cache** — Uses `actions/cache@v4` keyed on `pom.xml` hash. Avoids re-downloading all dependencies on every run (saves ~2-3 minutes).
- **Artifact upload** — The WAR file is saved as a GitHub Actions artifact so downstream jobs (Docker build) can use it without rebuilding.

**Best practice note:** The build happens once, and the artifact is shared. This follows the "build once, deploy everywhere" principle — the same WAR gets scanned and containerized, ensuring what you test is what you ship.

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

**What it does:** Scans the repository for accidentally committed secrets — API keys, passwords, tokens, private keys — using two complementary tools.

**Why two scanners?** No single open-source secrets scanner covers all secret types well. After testing Gitleaks, TruffleHog, Semgrep Secrets, detect-secrets, and Whispers (archived), the conclusion is:

| Tool | Provider tokens (AWS, GitHub, etc.) | Generic `password=value` in configs | Custom rules needed? |
|------|-------------------------------------|-------------------------------------|----------------------|
| **Gitleaks** | Excellent (~150 rules) | No | Yes (custom `.toml`) |
| **detect-secrets** | Limited | Excellent (KeywordDetector + entropy) | No |
| Combined | Excellent | Excellent | **No** |

**How Gitleaks works:**
1. ~150 built-in regex rules targeting specific secret formats (AWS access keys with `AKIA` prefix, GitHub tokens with `ghp_`, Slack webhooks, RSA private keys, etc.)
2. Scans files on disk in `--no-git` mode (bypasses git history, catches any secret currently present)
3. Outputs SARIF format

**How detect-secrets works:**
1. **KeywordDetector**: flags lines where keywords like `password`, `secret`, `token`, `api_key` appear in assignment context (e.g., `mysql.password=...`, `MYSQL_PASSWORD: ...`)
2. **HexHighEntropyString / Base64HighEntropyString**: flags values with high randomness that look like real credentials
3. Additional plugins for AWS keys, GitHub tokens, JWT, private keys, etc.
4. Outputs JSON with file paths, line numbers, and finding types

**Deduplication:** Both scanners' findings are merged in the issue creation step, deduplicated by `file:line` to avoid reporting the same secret twice.

**Scanning strategy:**
- **Default (push/PR):** Gitleaks `--no-git` + detect-secrets scan all files on disk. Fast and catches any secret currently in the codebase.
- **Full git-history audit:** Run `gitleaks detect --log-opts=--all` via `workflow_dispatch` to find secrets that were committed and later deleted (still in history, still need rotation).

**`continue-on-error: true`** — Secrets detection runs in **monitoring mode**. Even if secrets are found, the pipeline continues. This is a deliberate choice for early DevSecOps adoption: blocking on every finding creates friction. Once the backlog is cleared, switch to `continue-on-error: false` (blocking mode).

---

### Job 3: SAST — CodeQL

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

**What it does:** Static Application Security Testing (SAST) — analyzes the compiled Java bytecode for vulnerability patterns like SQL injection, command injection, XSS, and insecure data handling.

**How CodeQL works — a deeper look:**

CodeQL is fundamentally different from regex-based scanners. It works in three phases:

1. **Database creation:** During the Maven build, CodeQL's Java extractor hooks into the compiler. It captures the Abstract Syntax Tree (AST), type information, and control/data flow for every class. This creates a relational database of the entire codebase.

2. **Query execution:** CodeQL runs QL queries against this database. A query like "find SQL injection" is expressed as: *"Find a data flow path from an HTTP request parameter (source) to a SQL query string concatenation (sink), where no sanitization function appears on the path."*

3. **Result generation:** Matches are reported in SARIF format with the full data flow path — showing exactly how user input reaches the vulnerable code.

**Why CodeQL needs to build the code:**
Unlike simple text scanners, CodeQL needs the compiled bytecode to understand types, inheritance, and method resolution. When you call `entityManager.createQuery(str)`, CodeQL knows `entityManager` is a `javax.persistence.EntityManager` and `createQuery` is a sink for JPQL injection — because it resolved the types from the compiled classes.

**The `security-and-quality` query suite:**
This is CodeQL's extended query set. The default `security-extended` suite focuses purely on security. `security-and-quality` adds code quality rules that have security implications (like log injection). This is the recommended suite for security-focused pipelines.

**XML and properties file indexing:**
```yaml
- name: Index XML and properties files
  run: |
    codeql database index-files \
      --language xml \
      --include-extension .xml \
      -- ${{ runner.temp }}/codeql_databases/java
    codeql database index-files \
      --language xml \
      --include-extension .properties \
      -- ${{ runner.temp }}/codeql_databases/java
```

By default, CodeQL's Java extractor only captures `.java` and `.class` files. Configuration files like `struts.xml` and `config.properties` are invisible to queries unless explicitly indexed. This step adds them to the database, enabling:
- Detection of `struts.devMode=true` (security misconfiguration)
- Detection of hardcoded credentials in `.properties` files (CWE-555)

**Permissions:**
`security-events: write` is required because CodeQL uploads results to GitHub's Security tab (Code Scanning alerts), not just as a workflow artifact.

---

### Job 4: SCA — Trivy Dependencies

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

**What it does:** Software Composition Analysis (SCA) — identifies known vulnerabilities (CVEs) in third-party dependencies declared in `pom.xml`.

**How Trivy SCA works:**

1. **Dependency identification:** Trivy parses `pom.xml` (and resolves transitive dependencies via the Maven dependency tree) to build a list of `(groupId:artifactId, version)` tuples
2. **CVE matching:** Each dependency is checked against Trivy's vulnerability database (sourced from NVD, GitHub Advisory Database, and vendor-specific feeds)
3. **Severity classification:** Vulnerabilities are classified by CVSS score (CRITICAL >= 9.0, HIGH >= 7.0, etc.)

**Why two Trivy runs?**
The job runs Trivy twice with different output formats:

| Run | Format | Severity | Purpose |
|-----|--------|----------|---------|
| 1st | JSON | CRITICAL, HIGH, MEDIUM | Full detail for issue creation (includes descriptions, fix versions) |
| 2nd | SARIF | CRITICAL, HIGH | Uploaded to GitHub Security tab for integrated code scanning view |

The JSON includes MEDIUM severity for informational purposes, while the SARIF only includes CRITICAL and HIGH to avoid cluttering the Security tab.

**SCA vs SAST — the key difference:**

| | SAST (CodeQL) | SCA (Trivy) |
|--|---------------|-------------|
| **Analyzes** | Your code | Other people's code (dependencies) |
| **Finds** | Bugs you wrote | Bugs others wrote that you inherited |
| **Example** | SQL injection in `UserService.java` | CVE-2017-5638 in `struts2-core-2.3.30` |
| **Fix** | Rewrite the code | Update the dependency version |
| **False positives** | Possible (depends on data flow analysis accuracy) | Rare (version matching is deterministic) |
| **False negatives** | Common (limited to known patterns) | Possible (dependency not detected or CVE not yet published) |

**No `needs: build`** — Notice that Trivy SCA doesn't depend on the build job. It reads `pom.xml` directly; it doesn't need the compiled WAR. This means it can start immediately and run in parallel with everything else.

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

**What it does:** Packages the application into a Docker container image and pushes it to Docker Hub.

**Image tagging strategy:**
```yaml
tags: |
  type=sha,prefix=sha-          # sha-8c0bd80 (short commit SHA)
  type=ref,event=branch          # main (branch name)
  type=raw,value=${{ github.sha }}  # full SHA as exact reference
  type=raw,value=latest,enable=...  # 'latest' only on main/master
```

This produces multiple tags for the same image:
- **SHA-based tags** (`sha-8c0bd80`, full SHA) — immutable, uniquely identify a build. Used for traceability: "which exact code is running in production?"
- **Branch tag** (`main`) — mutable, always points to the latest build from that branch
- **`latest`** — conventional tag for the most recent stable build. Only applied on main/master.

**Best practice note:** Using the full commit SHA as the `IMAGE_TAG` environment variable ensures that the container scan (Job 6) scans the exact image that was just built, not a stale `latest` tag.

**Buildx and layer caching:**
```yaml
cache-from: type=gha
cache-to: type=gha,mode=max
```
This uses GitHub Actions' built-in cache for Docker layers. On subsequent builds, unchanged layers (like `apt-get install`) are cached, significantly reducing build time. `mode=max` caches all layers, including intermediate ones.

**The `.dockerignore` workaround:**
```yaml
- name: Remove target from .dockerignore
  run: sed -i '/^target/d' .dockerignore
```
The `.dockerignore` excludes `target/` (where Maven puts build output), but the Dockerfile needs the WAR from `target/`. Since the WAR was built in Job 1 and downloaded as an artifact, this step removes the ignore rule so Docker can see it.

---

### Job 6: Container Security — Trivy Image Scan

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

**What it does:** Scans the built Docker image for vulnerabilities in both OS packages and bundled libraries.

**How Trivy image scanning works (not DAST):**

This is a common misconception — Trivy does NOT run the container or send it HTTP requests. It works entirely offline:

1. **Pull the image** — Downloads the image from Docker Hub (a stack of tar archives called layers)
2. **Unpack the filesystem** — Extracts all layers to reconstruct the complete filesystem as it would appear inside a running container
3. **Identify OS packages** — Reads `/var/lib/dpkg/status` (Debian/Ubuntu), `/var/lib/rpm/` (RHEL), etc. to enumerate installed OS packages and versions
4. **Identify language libraries** — Walks the filesystem looking for:
   - `*.jar` files → reads `META-INF/MANIFEST.MF` and `pom.properties` inside each JAR
   - `package.json` / `node_modules` → Node.js dependencies
   - `go.sum` → Go modules
   - `requirements.txt` / `Pipfile.lock` → Python packages
5. **Match against CVE database** — Same process as SCA: check each `(package, version)` against known vulnerabilities

**`vuln-type: 'os,library'`:**

| Value | What it scans | Example findings |
|-------|--------------|-----------------|
| `os` | Only OS packages (apt, dpkg, rpm) | `libssl3` has CVE-2024-XXXX |
| `library` | Only language packages (JARs, npm, etc.) | `struts2-core-2.3.30.jar` has CVE-2017-5638 |
| `os,library` | Both | All of the above |

**Why scan the container if SCA already scans `pom.xml`?**

Defense-in-depth. The SCA step and the container scan serve different purposes:

| | SCA (Job 4) | Container Scan (Job 6) |
|--|-------------|----------------------|
| **Scans** | `pom.xml` (what you *declared*) | Docker image filesystem (what's *actually there*) |
| **Catches** | Vulnerable dependencies in source | Vulnerable packages in the deployed artifact |
| **Misses** | JARs manually copied into the image | Dependencies only in source, not in the final image |
| **When it runs** | Before build | After build |
| **Purpose** | Catch issues early | Verify the deployed artifact |

Example where they differ: If the Dockerfile copies an additional JAR (`COPY lib/legacy-util.jar /app/lib/`) that isn't in `pom.xml`, only the container scan would find it. Conversely, if a test-scope dependency in `pom.xml` isn't packaged into the WAR, SCA would flag it but the container scan wouldn't.

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

**What it does:** Aggregates findings from all four scanners, deduplicates them against existing open issues, and creates well-formatted GitHub Issues with structured metadata.

**This is the "last mile" of the pipeline** — translating scanner output into actionable developer tasks. Without this step, findings would exist only as artifacts or in the Security tab, which many developers don't regularly check.

**How findings are categorized:**

| Scanner | Issue prefix | Labels | Grouping strategy |
|---------|-------------|--------|-------------------|
| Trivy SCA | `[DEPENDENCY]` | `security`, `dependency`, severity | One issue per vulnerable package (groups all CVEs) |
| Trivy Image | `[CONTAINER]` | `security`, `container`, severity | One issue per vulnerable package |
| CodeQL | `[CODE]` | `security`, `code`, severity | One issue per rule (groups all locations) |
| Gitleaks + detect-secrets | `[SECRET]` | `security`, `secret`, `critical` | One combined issue, deduplicated by file:line |

**Deduplication strategy:**
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

**The 50-issue cap:**
```javascript
const MAX_ISSUES_PER_RUN = 50;
if (created >= MAX_ISSUES_PER_RUN) { capped++; continue; }
```
Prevents flooding the repository with hundreds of issues on the first run. Remaining findings are created in subsequent pipeline runs (they pass deduplication since the capped ones don't exist yet).

**Severity filtering in CodeQL:**
```javascript
const secSev = parseFloat(rule.properties?.['security-severity'] || '0');
if (secSev >= 9.0) severity = 'CRITICAL';
else if (secSev >= 7.0 || result.level === 'error') severity = 'HIGH';
else continue;  // skip MEDIUM and LOW
```
Only HIGH and CRITICAL findings become issues. This threshold aligns with industry practice — MEDIUM findings are still visible in the GitHub Security tab but don't create issue noise. The `security-severity` field comes from CodeQL's rule metadata and maps roughly to CVSS scores.

---

## 4. Security Testing Taxonomy

Understanding where each tool fits in the broader security testing landscape:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Security                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Pre-deployment (this pipeline)                      │   │
│  │                                                      │   │
│  │  ┌─────────────┐  ┌──────┐  ┌─────┐  ┌───────────┐  │   │
│  │  │   Secrets    │  │ SAST │  │ SCA │  │ Container │  │   │
│  │  │  Detection   │  │      │  │     │  │   Scan    │  │   │
│  │  │  (Gitleaks)  │  │(Code │  │(Tri │  │  (Trivy   │  │   │
│  │  │             │  │  QL) │  │ vy) │  │   Image)  │  │   │
│  │  └─────────────┘  └──────┘  └─────┘  └───────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Post-deployment (NOT in this pipeline)              │   │
│  │                                                      │   │
│  │  ┌──────┐  ┌─────────────┐  ┌───────────────────┐   │   │
│  │  │ DAST │  │  Pen Test   │  │ Runtime Security  │   │   │
│  │  │(ZAP) │  │  (Manual)   │  │   (WAF, RASP)     │   │   │
│  │  └──────┘  └─────────────┘  └───────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### What each approach finds

| Approach | Finds | Misses | Speed |
|----------|-------|--------|-------|
| **Secrets Detection** | Committed credentials, API keys, private keys, generic passwords in config files (via dual-scanner approach) | Secrets in binary files, encrypted/obfuscated values | Seconds |
| **SAST** | Injection flaws, unsafe crypto, data exposure — in your code | Logic flaws, missing controls (CSRF, IDOR), cross-language flows | Minutes |
| **SCA** | Known CVEs in declared dependencies | Zero-day vulnerabilities, vulnerabilities in undeclared/transitive dependencies not in DB | Seconds |
| **Container Scan** | OS and library vulnerabilities in the deployed image | Application-level vulnerabilities (those need SAST/DAST) | Seconds-Minutes |
| **DAST** | XSS, CSRF, IDOR, auth bypass, open redirect — anything exploitable at runtime | Requires a running application; slower; can't find all code paths | Minutes-Hours |
| **Pen Test** | Business logic flaws, chained exploits, real-world attack scenarios | Expensive, infrequent, dependent on tester skill | Days |

**This pipeline covers the first four.** The notable gap is DAST — which would catch XSS, IDOR, CSRF, and other runtime vulnerabilities that static tools miss.

---

## 5. Report Format: SARIF

All scanners in this pipeline produce **SARIF** (Static Analysis Results Interchange Format) — an OASIS standard JSON format for static analysis output.

**Why SARIF matters:**
- **Universal format:** CodeQL, Trivy, Gitleaks, Semgrep, ESLint, and hundreds of other tools all speak SARIF
- **GitHub integration:** GitHub's Code Scanning tab natively consumes SARIF via `codeql-action/upload-sarif`
- **Structured data:** Each finding has a rule ID, severity, file location, message, and remediation guidance — machine-parseable for automation

**SARIF structure (simplified):**
```json
{
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [
          {
            "id": "java/sql-injection",
            "shortDescription": { "text": "Query built from user-controlled sources" },
            "properties": { "security-severity": "8.8" }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "java/sql-injection",
        "level": "error",
        "message": { "text": "This query depends on a user-provided value." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/main/java/.../UserService.java" },
            "region": { "startLine": 75 }
          }
        }]
      }
    ]
  }]
}
```

The pipeline's Job 7 (issue creation) parses this structure to extract rule metadata, severity, file locations, and messages — then formats them into GitHub Issues.

---

## 6. Issue Management Strategy

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

### Label Taxonomy

| Label | Color | Purpose |
|-------|-------|---------|
| `security` | Red | Applied to all findings — enables filtering |
| `critical` | Dark Red | CVSS >= 9.0 or security-severity >= 9.0 |
| `high` | Orange | CVSS >= 7.0 or security-severity >= 7.0 |
| `dependency` | Purple | Vulnerable third-party library (SCA) |
| `container` | Blue | Vulnerability in Docker image |
| `code` | Green | Source code vulnerability (SAST) |
| `secret` | Red | Exposed credential |

These labels allow developers to filter and prioritize:
- "Show me all `critical` + `code` issues" → highest priority code fixes
- "Show me all `dependency` issues" → batch dependency update
- "Show me all `container` issues" → base image or Dockerfile changes

---

## 7. Best Practices Comparison

### What this pipeline does well

| Practice | Implementation | Why it matters |
|----------|---------------|---------------|
| **Shift-left security** | Runs on every push and PR | Developers get feedback before merging |
| **Non-blocking scans** | `continue-on-error: true` | Doesn't break developer workflow during adoption |
| **Multiple scan types** | Secrets + SAST + SCA + Container | Defense-in-depth — no single tool catches everything |
| **SARIF standardization** | All tools output SARIF | Unified format for GitHub Security tab integration |
| **Issue deduplication** | Title-based matching against open issues | No duplicate noise across runs |
| **Rate limit handling** | 1-second delay + graceful stop on 403 | Robust against GitHub API limits |
| **Immutable image tags** | `IMAGE_TAG: ${{ github.sha }}` | Exact traceability between code and container |
| **Build artifact reuse** | WAR uploaded once, downloaded by Docker job | Build once, deploy everywhere |
| **Layer caching** | Maven cache + Docker Buildx GHA cache | Faster pipeline runs (minutes saved) |
| **Severity filtering** | Only CRITICAL + HIGH create issues | Focused signal, not noise |
| **Parallel execution** | Jobs 2-5 run concurrently | Pipeline completes faster |

### Areas for improvement

| Gap | Current state | Best practice | Recommendation |
|-----|--------------|---------------|----------------|
| **No DAST** | Only static analysis | Include dynamic testing | Add OWASP ZAP against the running container |
| **No blocking gate** | All scans are `continue-on-error: true` | Block on CRITICAL findings | Set `exit-code: '1'` for CRITICAL severity in Trivy; remove `continue-on-error` once backlog is cleared |
| **No SLA tracking** | Issues are created but not time-tracked | Enforce fix SLAs | Add due dates: CRITICAL = 7 days, HIGH = 30 days |
| **No auto-close** | Fixed vulnerabilities stay open | Auto-close when fixed | Add a job that closes issues when the vulnerability no longer appears |
| **Secrets coverage** | ~~Default Gitleaks rules only~~ **Resolved** | Catch generic passwords in config files | Added **detect-secrets** as a complementary scanner — its KeywordDetector + entropy plugins catch `password=value` patterns that Gitleaks intentionally skips |
| **No IaC scanning** | Dockerfile not scanned for misconfigurations | Scan Dockerfiles and compose files | Add `trivy config .` or Hadolint for Dockerfile best practices |
| **No SBOM generation** | Dependencies listed only in scan results | Generate and publish an SBOM | Add `trivy sbom --format cyclonedx` for supply chain transparency |
| **Tests skipped** | `-DskipTests` in build | Run tests as part of CI | Add a test stage (or at least don't skip in production pipeline) |
| **Pinned action versions** | `aquasecurity/trivy-action@master` | Pin to specific SHA or version tag | Use `@0.28.0` or SHA to prevent supply chain attacks via compromised action |

### Action version pinning — a security note

```yaml
uses: aquasecurity/trivy-action@master       # current — risky
uses: aquasecurity/trivy-action@0.28.0       # better — pinned to version
uses: aquasecurity/trivy-action@abc123def... # best — pinned to commit SHA
```

Using `@master` means the action code can change without your knowledge. A compromised or malicious update to the action's `master` branch could exfiltrate secrets from your pipeline. Pinning to a specific version or SHA is a supply chain security best practice, recommended by GitHub themselves.

---

## 8. Known Limitations and Trade-offs

### `continue-on-error: true` — Monitoring vs Enforcement

Every security job in this pipeline uses `continue-on-error: true`. This means:

- **Pro:** The pipeline never breaks. Developers aren't blocked by security findings.
- **Con:** There's no enforcement. A developer can merge code with critical vulnerabilities because the pipeline always succeeds.

This is the right approach for **initial adoption** of DevSecOps — you want to build trust and clear the backlog of findings before turning on enforcement. The maturity progression looks like:

```
Stage 1: Monitor         → continue-on-error: true, create issues
Stage 2: Warn            → continue-on-error: true, add PR comments
Stage 3: Block CRITICAL  → exit-code: 1 for CRITICAL only
Stage 4: Block HIGH+     → exit-code: 1 for HIGH and CRITICAL
Stage 5: Full enforcement → Required status checks, branch protection
```

### Build duplication

The pipeline builds the application **twice**:
1. Job 1 (Build) — produces the WAR artifact
2. Job 3 (CodeQL) — builds again because CodeQL needs to observe the compilation

This is unavoidable with CodeQL's architecture — it needs to intercept the compiler during build. The Maven cache mitigates the time cost.

### Trivy SCA scans `pom.xml` declaratively

Trivy's filesystem scan reads `pom.xml` but doesn't resolve the full Maven dependency tree the way `mvn dependency:tree` would. This means:
- **Direct dependencies** in `pom.xml` are always detected
- **Transitive dependencies** are resolved using Trivy's built-in resolver, which may not match Maven's exact resolution in edge cases (version conflicts, exclusions, BOMs)

For maximum accuracy, you could add a step that runs `mvn dependency:tree -DoutputFile=deps.txt` and feed that to a more precise scanner.

---

## 9. What Each Tool Can and Cannot Find

### Applied to DVJA's known vulnerabilities

| Vulnerability | Gitleaks | detect-secrets | CodeQL | Trivy SCA | Trivy Container | DAST (not in pipeline) |
|--------------|----------|---------------|--------|-----------|-----------------|----------------------|
| **SQL Injection** (A1) | | | **YES** | | | YES |
| **Command Injection** (A1) | | | **YES** | | | YES |
| **XSS — Reflected** (A3) | | | Partial | | | **YES** |
| **XSS — Stored** (A3) | | | Partial | | | **YES** |
| **Broken Auth** — MD5 reset token (A2) | | | | | | **YES** |
| **Broken Auth** — MD5 password hashing (A2) | | | Partial | | | |
| **IDOR** (A4) | | | | | | **YES** |
| **Security Misconfiguration** — devMode (A5) | | | **YES** (with XML indexing) | | | |
| **Sensitive Data in Logs** (A6) | | | **YES** | | | |
| **Admin Bypass via Cookie** (A7) | | | | | | **YES** |
| **CSRF** (A8) | | | | | | **YES** |
| **Struts2 CVE-2017-5638** (A9) | | | | **YES** | **YES** | YES |
| **Log4Shell CVE-2021-44228** | | | | **YES** | **YES** | YES |
| **Open Redirect** (A10) | | | | | | **YES** |
| **Hardcoded credentials** in config.properties | | **YES** (KeywordDetector) | **YES** (with .properties indexing) | | | |
| **Hardcoded credentials** in docker-compose.yml | | **YES** (KeywordDetector + HexHighEntropy) | | | | |
| **Log Injection** (CWE-117) | | | **YES** | | | |

**Key takeaway:** No single tool catches everything. The value of a DevSecOps pipeline is the **combination** of multiple tools, each covering different blind spots. The dual-scanner approach for secrets (Gitleaks for provider tokens + detect-secrets for generic passwords) is a good example: neither tool alone covers all secret types, but together they provide comprehensive coverage. Even with all five tools in this pipeline, DAST and manual review are still needed for a complete security posture.

---

## Glossary

| Term | Definition |
|------|-----------|
| **SAST** | Static Application Security Testing — analyzes source code or bytecode without running the application |
| **DAST** | Dynamic Application Security Testing — tests a running application by sending requests and analyzing responses |
| **SCA** | Software Composition Analysis — identifies known vulnerabilities in third-party dependencies |
| **SARIF** | Static Analysis Results Interchange Format — standardized JSON format for tool output |
| **CVE** | Common Vulnerabilities and Exposures — unique identifier for a publicly known vulnerability |
| **CWE** | Common Weakness Enumeration — categorization of software weakness types |
| **CVSS** | Common Vulnerability Scoring System — numerical score (0-10) indicating vulnerability severity |
| **OWASP** | Open Web Application Security Project — nonprofit producing security standards and tools |
| **SBOM** | Software Bill of Materials — inventory of all components in a software product |
| **WAR** | Web Application Archive — Java packaging format for web applications |
| **OGNL** | Object-Graph Navigation Language — expression language used by Struts2 (often exploited in RCE) |
| **JPQL** | Java Persistence Query Language — SQL-like language for JPA queries (vulnerable to injection like SQL) |
| **IaC** | Infrastructure as Code — managing infrastructure through configuration files (Dockerfiles, Terraform, etc.) |
