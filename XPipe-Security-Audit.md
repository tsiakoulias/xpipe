# Security Audit — XPipe

**Date:** 2026-02-21  
**Repository:** `xpipe-io/xpipe`  
**Scope:** Full source code security review (Java/Gradle desktop application)

---

## Overview

XPipe is a Java desktop application (JavaFX) that manages shell connections to local and remote servers. It exposes a local HTTP API ("Beacon") on `127.0.0.1` for inter-process communication and an MCP server for AI tool integration. The application handles sensitive credentials, SSH keys, and arbitrary command execution across connected systems.

This audit identified **136 numbered tasks** across the codebase, categorized by severity. Each finding is numbered as a discrete task suitable for a separate fix branch and pull request.

### Findings Organization

Tasks are numbered by priority (**Task 1 = highest priority**) based primarily on **CVSS v4.0** base score (tie-breakers: CVSS severity label, Category, then original task ID).

**Reporting note (default posture):** Some findings only become exploitable (or materially worse) when a user enables an insecure, non-default setting (e.g., disabling API auth, disabling TLS validation) or when diagnostic logging is enabled. Those tasks are explicitly marked **Non-default prerequisite** and their **Severity** is **demoted for default-configuration reporting**, while the **CVSS v4.0** line is retained as the *worst-case* score under the stated precondition.

### Severity Summary

| Severity     | Count | Key Themes                                                              |
|--------------|-------|-------------------------------------------------------------------------|
| **CRITICAL** | 2     | Broken encryption                                                       |
| **HIGH**     | 16     | TLS bypass, timing attacks, deserialization, API abuse, command injection, SSH bridge hardening, vault encryption gaps, RDP certificate bypass |
| **MEDIUM**   | 55     | Command injection, protocol/parser bugs, stream size handling, UI phishing, SSH agent/bridge lifecycle, Git security, credential safety, RDP protocol security |
| **LOW**      | 59     | Supply chain, hardcoded DSN, temp/memory lifecycle, auth hardening gaps, SSH config isolation, Git audit logging |
| **INFO**     | 4     | Design observations and structural risks                                |

**Total: 136 security findings**

### CVSS v4.0 Scoring

Each finding includes a **CVSS v4.0** (Common Vulnerability Scoring System version 4.0) base score computed using the [FIRST.org specification](https://www.first.org/cvss/v4-0/). Scores were calculated programmatically using the RedHat `cvss` Python library (v3.6) from individually assessed base metric vectors.

**Scoring context:** XPipe is a local desktop application, but its CORS wildcard (`*`) on the Beacon API means browser-based cross-origin requests can reach `127.0.0.1`, elevating many API findings to `AV:N`. Findings affecting credentials or SSH keys carry subsequent-system impact (`SC:H`/`SI:H`) because XPipe manages connections to many downstream servers.

## Findings

---

### Task 1 — SSH Client Connections Do Not Enforce Host-Key Verification
- **Severity:** HIGH
- **Category:** Man-in-the-Middle / Authentication
- **Files:**
  - `app/src/main/java/io/xpipe/app/secret/SecretManager.java` (host key trust prompt handling)
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/NoIdentityStrategy.java` (represents how SSH options are built for identity selection; no host-key policy here)
  - SSH connection providers (implementation may be outside this source tree)
- **CWE:** CWE-322 (Key Exchange without Entity Authentication)
- **Verification:** Partially valid - no explicit host-key policy (`StrictHostKeyChecking`, `UserKnownHostsFile`, etc.) is visible in this tree, but the app does include explicit handling for SSH host-key trust prompts; effective runtime behavior depends on the underlying SSH client/library and user config.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**

Outbound SSH connections initiated by XPipe connectors do not visibly set an explicit host-key verification policy (e.g., `StrictHostKeyChecking` / managed `UserKnownHostsFile`) anywhere in the visible source tree. However, the app does contain explicit handling for SSH host-key trust prompts, so host-key verification is not provably disabled from this tree alone. The effective behavior at runtime depends on the SSH implementation and the user's SSH configuration.

**Why It Matters:**

Without strict host-key checking a compromised network device or DNS-spoofing attack can intercept SSH sessions to managed nodes. All credentials and commands sent after the handshake are exposed to the adversary.

**Recommended Fix:**

Explicitly set `StrictHostKeyChecking yes` for all production connections. Provide an explicit `known_hosts` file path under XPipe's data directory so users have a managed, auditable set of trusted keys.


---

### Task 2 — `SshIdentityStrategy` Lacks Explicit `StrictHostKeyChecking` Configuration
- **Severity:** HIGH
- **Category:** Man-in-the-Middle / Authentication
- **Files:** `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStrategy.java`
- **CWE:** CWE-322 (Key Exchange without Entity Authentication)
- **Verification:** Confirmed - StrictHostKeyChecking not set in any identity strategy.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**

Connection strategies that inject identity files into the SSH invocation do not also inject `-o StrictHostKeyChecking=yes`, leaving the host verification posture at whatever the user's `~/.ssh/config` specifies (often `ask`, which in a GUI launch may silently accept unknown keys).

**Why It Matters:**

Every outbound connection that does not explicitly opt-in to strict checking is potentially susceptible to host impersonation.

**Recommended Fix:**

Every code path that constructs an SSH command or JSch `Session` must explicitly set `StrictHostKeyChecking yes` (or the library equivalent). Deviations should require explicit user opt-in with a clear warning in the UI.


---

### Task 3 — Snapshot Maven Repository Enabled Globally
- **Severity:** LOW
- **Category:** Supply Chain
- **File:** `build.gradle` — line 30
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - Snapshot repository in allprojects.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The Sonatype snapshots repository is configured in the `allprojects` block, meaning all subprojects resolve from it. Snapshot artifacts are mutable and unsigned — they can change at any time without notice.

```groovy
maven {
    url = uri("https://central.sonatype.com/repository/maven-snapshots")
}
```

**Remediation:**
- Restrict snapshot repository usage to development builds only (e.g., guard with `if (!isFullRelease)`).
- Production/release builds should never resolve from snapshot repositories.


---

### Task 4 — Remmina RDP Integration Disables Certificate Validation by Default (`cert_ignore=1`)
- **Severity:** HIGH
- **Category:** Transport Security
- **File:** `app/src/main/java/io/xpipe/app/util/RemminaHelper.java` — line 77
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Verification:** Confirmed - cert_ignore=1 hardcoded in Remmina profile.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The generated Remmina RDP profile hard-codes `cert_ignore=1`:

```ini
cert_ignore=1
```

This disables certificate validation for the RDP connection.

**Impact:**  
Enables man-in-the-middle interception/modification of RDP traffic when connecting over untrusted networks, including credential capture and session hijacking depending on the RDP security mode.

**Remediation:**
- Do not disable certificate validation by default.
- If self-signed servers are common, provide an explicit user opt-in per connection (with a clear warning) or implement a pinning/TOFU approach.
- Ensure generated profiles reflect the user’s chosen security posture.


---

### Task 5 — No SSL/TLS Certificate Validation Configuration for Git Over HTTPS
- **Severity:** HIGH
- **Category:** Transport Security
- **Files:**
  - `app/src/main/java/io/xpipe/app/ext/ProcessControlProvider.java` — lines 78–80 (interface definition)
  - Git implementation (not visible in this source tree)
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Verification:** Confirmed - ProcessControlProvider.cloneRepository(String, Path) interface exposes no TLS configuration parameters; callers cannot enforce or verify certificate validation, and the closed-source ServiceLoader implementation is unauditable.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The `ProcessControlProvider` interface does not expose any mechanism to configure or validate TLS certificates for Git HTTPS operations. When cloning from `https://` URLs, transport security behavior is delegated entirely to the ServiceLoader-provided Git implementation (not visible/auditable in this source tree):

```java
public abstract void cloneRepository(String url, Path target) throws Exception;
public abstract void pullRepository(Path target) throws Exception;
```

This repository therefore cannot prove whether TLS verification is enforced, whether global Git config can disable verification, or whether certificate pinning is supported.

**Impact:**  
If the underlying Git implementation does not strictly enforce TLS verification (or can be made to skip verification via global configuration), a network-path attacker could serve a malicious Git repository during clone operations, enabling:
- Code injection (if scripts are loaded from the repo)
- Supply-chain poisoning (if icons/resources are downloaded)
- Credential exfiltration if git stores credentials

**Remediation:**
- Explicitly configure Git's `http.sslVerify=true` and ensure it's not disabled globally.
- Add an option to pin expected certificate fingerprints or download a known-good certificate during setup.
- Validate that Git commands execute with `core.sslVerify=true` enforced.
- Consider using SSH-based Git URLs (with SSH key pinning) for critical repositories instead of HTTPS.
- Add a verification step post-clone to check repository content integrity (e.g., verify a signed tag or commit).


---

### Task 6 — FreeRdp Client Hardcodes `/cert:ignore` Flag (Certificate Validation Bypass)
- **Severity:** HIGH
- **Category:** Transport Security / RDP Protocol
- **File:** `app/src/main/java/io/xpipe/app/rdp/FreeRdpClient.java` — lines 48–49
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Verification:** Confirmed - /cert:ignore (v3) and /cert-ignore (v2) hardcoded.
- **CVSS v4.0:** 9.4 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The FreeRdp integration hardcodes the `/cert:ignore` (xfreerdp3) or `/cert-ignore` (xfreerdp2) flag unconditionally when launching every RDP connection:

```java
var b = CommandBuilder.of()
        .add(exec)
        .addFile(file.toString())
        .add(v3 ? "/cert:ignore" : "/cert-ignore")  // Always disables cert validation
        .add("/dynamic-resolution")
        .add("/network:auto")
        // ...
```

The flag is hardcoded and unconditional — every RDP connection via FreeRdp disables server certificate validation regardless of whether the server presents a self-signed, expired, mismatched, or malicious certificate.

**Impact:**  
- Enables man-in-the-middle (MITM) attacks on RDP traffic over any untrusted network.
- NLA credential capture: attacker forges the RDP server and harvests username/password.
- Session hijacking and clipboard/keystroke injection by an attacker in a network position.
- No differentiation between self-signed (potentially legitimate) and malicious certificates — all are silently accepted.

**Remediation:**
- Remove the hardcoded `/cert:ignore` flag entirely.
- Implement a TOFU (Trust-On-First-Use) model: cache the server certificate fingerprint on first connection and validate on subsequent ones.
- Expose a per-connection opt-in checkbox (`Ignore certificate`) with a prominent MitM warning in the UI.
- For known self-signed certificates, provide a guided flow to extract and trust the specific certificate rather than globally disabling validation.


---

### Task 7 — MCP `run_script` Tool Appends Unquoted `arguments` Directly to Shell Command
- **Severity:** LOW
- **Category:** Command Injection
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/mcp/McpTools.java` — lines 387–389
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Verification:** Confirmed - run_script uses raw string concatenation of arguments.
- **Non-default prerequisite:** Requires `enableMcpServer` and `enableMcpMutationTools` to be enabled (both default to disabled).
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes MCP is enabled, mutation tools are enabled, and an attacker has MCP access/token)*

**Description:**  
The `run_script` MCP tool retrieves the caller-supplied `arguments` string from the request and concatenates it without any quoting or sanitization onto the assembled shell script command:

```java
var arguments = req.getStringArgument("arguments");
...
var out = shellSession.getControl()
    .command(
        shellSession.getControl().getShellDialect()
            .runScriptCommand(shellSession.getControl(), scriptFile.toString())
        + arguments)   // raw concat — no quoting
    .withWorkingDirectory(directory)
    .readStdoutOrThrow();
```

For a bash target, `runScriptCommand` produces something like `bash /tmp/xpipe-script-XYZ.sh`. Supplying `arguments = " ; id"` yields the executed string `bash /tmp/xpipe-script-XYZ.sh ; id`, allowing arbitrary command execution.

**Impact:**  
Any MCP client (e.g., an AI agent using the MCP server) can achieve full remote code execution on every system connected to XPipe by passing crafted `arguments`. Prompt-injection attacks on the AI layer can weaponize this without user awareness. Since MCP mutation tools require authentication, the immediate attacker model is a compromised token or a prompt-injection chain from an LLM.

**Remediation:**
- Pass `arguments` as a properly quoted element through `CommandBuilder.addQuoted()` or the target shell's quoting dialect, not by raw string concatenation.
- Alternatively, accept script arguments as a JSON array and quote each token individually before appending.
- Consider disallowing shell metacharacters in the `arguments` field via allowlist validation.


---

### Task 8 — Unsanitized Shell Command Execution via /shell/exec API
- **Severity:** MEDIUM
- **Category:** Command Injection / API Security
- **File:** `app/src/main/java/io/xpipe/app/beacon/impl/ShellExecExchangeImpl.java` — line 20
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - Direct command execution by design.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes the HTTP API is enabled)*

**Description:**  
The `command` field from the HTTP request body is passed directly to `ShellControl.command()` with zero sanitization or validation:

```java
try (var command = existing.getControl().command(msg.getCommand()).start()) {
```

While this is authenticated and the API is designed for command execution, there is no rate limiting, command allowlisting, audit logging, or scope restriction. Combined with the CORS wildcard (Task 16), this becomes exploitable from a browser.

**Impact:**  
Arbitrary command execution on any connected shell session — local or remote.

**Remediation:**
- This is inherently a command execution endpoint, so full sanitization isn't feasible. Instead:
  - Ensure CORS is restricted (Task 16).
  - Ensure authentication cannot be disabled (Task 16).
  - Add audit logging for all commands executed via the API.
  - Consider an explicit user confirmation prompt for API-initiated commands.


---

### Task 9 — Deterministic PRNG for Cryptographic Salt and Nonce (AES-GCM Nonce Reuse)
- **Severity:** CRITICAL
- **Category:** Cryptography
- **Files:**
  - `core/src/main/java/io/xpipe/core/InPlaceSecretValue.java` — lines 34, 64
  - `app/src/main/java/io/xpipe/app/secret/EncryptionKey.java` — lines 30, 40
- **CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-323 (Reusing a Nonce/IV with CBC/GCM)
- **Verification:** Confirmed - Fixed-seed Random for salt/nonce; deterministic crypto parameters.
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
`java.util.Random` is instantiated with hardcoded seeds to generate AES-GCM salts and nonces. Because `Random` is a deterministic PRNG and the seed is constant, the **exact same salt and nonce are produced on every invocation**, across every installation of XPipe.

```java
// InPlaceSecretValue.java:34 — static salt
var salt = new byte[SALT_BIT];
new Random(AES_KEY_BIT).nextBytes(salt);

// InPlaceSecretValue.java:64 — static nonce
new Random(1 - 28 + 213213).nextBytes(nonce);

// EncryptionKey.java:30, 40 — static salt for vault/legacy keys
new Random(128).nextBytes(salt);
```

**Impact:**  
AES-GCM **requires unique nonces**. Reusing a nonce with the same key:
- Allows XOR of ciphertexts to recover plaintext
- Breaks GCM's authentication tag (forgery becomes trivial)
- Renders the entire encryption scheme ineffective

The static salt reduces PBKDF2 key derivation to a fixed function, enabling precomputation / rainbow table attacks.

**Remediation:**
- Replace `new Random(seed)` with `new SecureRandom()` for all cryptographic material.
- Generate a unique random salt per encryption operation and store it alongside the ciphertext.
- Generate a unique random nonce per encryption operation (12 bytes for GCM) and prepend it to the ciphertext.


---

### Task 10 — Hardcoded Encryption Key in InPlaceSecretValue
- **Severity:** CRITICAL
- **Category:** Cryptography
- **File:** `core/src/main/java/io/xpipe/core/InPlaceSecretValue.java` — line 35
- **CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)
- **Verification:** Confirmed - Hardcoded 3-char passphrase, only 2048 PBKDF2 iterations.
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The AES secret key is derived from a hardcoded password `{'X', 'P', (char)('E' << 1)}` using PBKDF2 with only 2,048 iterations and a deterministic salt (see Task 9). This key is a compile-time constant — identical across every XPipe installation worldwide.

```java
KeySpec spec = new PBEKeySpec(
    new char[] {'X', 'P', 'E' << 1},  // hardcoded password
    salt,                               // deterministic salt (Task 1)
    ITERATION_COUNT,                    // 2048 — far below OWASP minimum of 600,000
    AES_KEY_BIT                         // 128
);
SECRET_KEY = new SecretKeySpec(SECRET_FACTORY.generateSecret(spec).getEncoded(), "AES");
```

**Impact:**  
Anyone with access to the source code (or a JAR decompiler) can reconstruct the exact AES key and decrypt all `InPlaceSecretValue`-encrypted data. This is obfuscation, not encryption.

**Remediation:**
- Derive encryption keys from a per-installation secret (e.g., a randomly generated master key stored in the OS keychain).
- Use PBKDF2 with ≥600,000 iterations (OWASP 2023 recommendation) or switch to Argon2id.
- Note: The newer `EncryptionKey.getEncryptedKey()` already uses 600,000 iterations — migrate `InPlaceSecretValue` to use the same approach.


---

### Task 11 — API File Operations Without Path Scope Validation
- **Severity:** MEDIUM
- **Category:** File Access Control / API Security
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/impl/FsReadExchangeImpl.java`
  - `app/src/main/java/io/xpipe/app/beacon/impl/FsWriteExchangeImpl.java`
  - `app/src/main/java/io/xpipe/app/beacon/impl/FsScriptExchangeImpl.java`
- **CWE:** CWE-22 (Path Traversal)
- **Verification:** Confirmed - FsReadExchangeImpl and FsWriteExchangeImpl pass client-supplied FilePath directly to fs.openInput()/openOutput() with no normalization, scoping, or traversal checks.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes the HTTP API is enabled)*

**Description:**  
The `/fs/read`, `/fs/write`, and `/fs/script` endpoints accept a `FilePath` from the JSON request body and pass it directly to the underlying file system with no explicit base-path scoping or authorization checks:

```java
// FsReadExchangeImpl.java — reads any file
try (var in = fs.openInput(msg.getPath())) {
  var fixedIn = new FixedSizeInputStream(new BufferedInputStream(in), size);
  bytes = fixedIn.readAllBytes();
}

// FsWriteExchangeImpl.java — writes any file
try (var in = BlobManager.get().getBlob(msg.getBlob());
    var os = fs.openOutput(msg.getPath(), in.available())) {
  in.transferTo(os);
}
```

The `FilePath` class has a `normalize()` method, but it is never called as a validation step in these handlers. For remote shells, the path flows into shell commands via string interpolation.

**Impact:**  
An authenticated API client can read or write any file accessible to the shell session, including sensitive system or credential files. This is primarily an **authorization/scope control weakness** on filesystem APIs.

**Remediation:**
- Call `FilePath.normalize()` and validate that the resolved path is within an expected base directory.
- Reject paths containing `..` segments after normalization.
- Add audit logging for all file operations via the API.
- Ensure CORS and auth fixes from Task 16 are applied.


---

### Task 12 — Git Repository URL Not Validated Before Clone/Pull Operations
- **Severity:** HIGH
- **Category:** Input Validation / URL Handling
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 115–141
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 109–116
  - `app/src/main/java/io/xpipe/app/ext/ProcessControlProvider.java` — lines 78–80
- **CWE:** CWE-20 (Improper Input Validation), CWE-94 (Code Injection)
- **Verification:** Confirmed - No URL validation before git clone.
- **CVSS v4.0:** 9.3 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
Git repository URLs are accepted from user input (UI text fields, configuration files) with **no validation** before being passed to `ProcessControlProvider.cloneRepository(url, path)`:

```java
// ScriptCollectionSource.java:140
ProcessControlProvider.get().cloneRepository(url, getLocalPath());

// SystemIconSource.java:112
ProcessControlProvider.get().cloneRepository(remote, dir);
```

The URL is not validated for:
- Malicious schemes (`file://`, `git://` with no auth, etc.)
- Shell metacharacters or command injection payloads
- Overly-long URLs (buffer/DoS)
- Credential embedding (e.g., `https://user:password@host/repo.git`)

**Impact:**  
An attacker can:
1. Supply a `file://` URL to clone from a local path (unexpected local-source behavior in a feature intended for remote repositories).
2. Supply a URL containing shell metacharacters **if** the Git implementation ultimately executes a shell command (this behavior is implementation-dependent and is not auditable from this tree).
3. Exfiltrate credentials embedded in URLs (if the user pastes them).
4. Trigger a DoS by supplying an extremely long URL.
5. Point to a malicious Git server that serves arbitrary code.

**Remediation:**
- Validate repository URLs:
  ```java
  try {
      var uri = new URI(url);
      if (!uri.getScheme().matches("(https?|ssh|git)")) {
          throw new ValidationException("Invalid Git scheme: " + uri.getScheme());
      }
      if (url.length() > 2048) {
          throw new ValidationException("Repository URL exceeds max length");
      }
  } catch (URISyntaxException e) {
      throw new ValidationException("Invalid repository URL: " + e.getMessage());
  }
  ```
- Reject `file://` URLs outright.
- Add allowlist for known-safe Git hosting providers (GitHub, GitLab, Gitea, etc.).
- Warn users if URLs contain embedded credentials.


---

### Task 13 — `ForceCommand` References `$SSH_ORIGINAL_COMMAND` Without Quoting
- **Severity:** HIGH
- **Category:** Command Injection
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Verification:** Confirmed - Unquoted $SSH_ORIGINAL_COMMAND in ForceCommand.
- **CVSS v4.0:** 9.2 (Critical) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**

The bridge generates `sshd_config` with a `ForceCommand` value that is assembled from the CLI path plus the shell dialect’s `SSH_ORIGINAL_COMMAND` variable, without quoting/escaping that variable expansion:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
        var command = "\"" + AppInstallation.ofCurrent().getCliExecutablePath() + "\" ssh-launch "
                + sc.getShellDialect().environmentVariable("SSH_ORIGINAL_COMMAND");
```

A client that sends a crafted SSH exec request can inject additional shell tokens into the command.

**Why It Matters:**

If the `ForceCommand` shell evaluates the unquoted variable, an attacker-controlled SSH client can append arbitrary shell commands executed under the bridge's privileges.

**Recommended Fix:**

Wrap the variable reference in double-quotes: `"$SSH_ORIGINAL_COMMAND"`. Alternatively, pass the value via an environment variable to the bridge process without shell interpolation by using `AcceptEnv` + explicit argument parsing.


---

### Task 14 — Oh-My-Zsh Prompt Installer Executes Remote Script From Mutable GitHub Branch
- **Severity:** LOW
- **Category:** Supply Chain / Integrity
- **Files:**
  - `app/src/main/java/io/xpipe/app/terminal/OhMyZshTerminalPrompt.java` — lines 133–136
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - curl pipe sh from mutable GitHub branch.
- **CVSS v4.0:** 9.1 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The Oh-My-Zsh prompt installer executes a remote script directly via command substitution:

```java
sc.command(
    "KEEP_ZSHRC=yes ZSH=\"" + configDir
        + "\" sh -c \"$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\" \"\" --unattended")
    .execute();
```

This fetches and executes from `raw.githubusercontent.com/.../master/...` (a mutable branch) without any signature/checksum verification or pinning to a known-good revision.

**Impact:**  
If the distribution chain is compromised (upstream repo compromise, GitHub account compromise, DNS/TLS interception in weakened environments), the installer can execute arbitrary attacker-supplied code during prompt installation.

**Remediation:**
- Prefer downloading a versioned release artifact and verifying checksum/signature before execution.
- Pin to a specific tag/commit hash and fail closed if content differs.
- Consider shipping prompt installers as embedded scripts/resources rather than executing from remote at install time.


---

### Task 15 — TLS Certificate Validation Bypass (Trust-All X509TrustManager)
- **Severity:** LOW
- **Category:** Transport Security
- **File:** `app/src/main/java/io/xpipe/app/util/HttpHelper.java` — lines 22–36
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Verification:** Confirmed - Trust-all TLS gated behind a preference toggle.
- **Non-default prerequisite:** User must explicitly enable `disableHttpsTlsCheck` (non-default/insecure).
- **CVSS v4.0:** 9.1 (Critical) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` *(worst-case only when `disableHttpsTlsCheck` is enabled)*

**Description:**  
When the `disableHttpsTlsCheck` preference is enabled, a `TrustAllCerts` X509TrustManager is installed that accepts any certificate — self-signed, expired, wrong hostname, revoked:

```java
var trustManager = new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[] {}; }
};
sslContext.init(null, new TrustManager[] {trustManager}, new SecureRandom());
```

This is also surfaced as a normal toggle in the Security settings UI (`SecurityCategory.java`), which normalizes disabling TLS.

**Impact:**  
Enables trivial man-in-the-middle interception and modification of all HTTPS traffic issued by the application (update checks, API calls, extension downloads, etc.).

**Remediation:**
- If self-signed certificate support is needed, implement a certificate pinning or trust-on-first-use (TOFU) model instead of trust-all.
- At minimum, add a prominent warning dialog each time the app starts with TLS disabled.
- Consider removing the option entirely in favor of a custom truststore approach.


---

### Task 16 — CORS Wildcard Combined with Disableable Authentication Enables Remote Code Execution
- **Severity:** MEDIUM
- **Category:** API Security / CORS / CSRF
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — line 188
  - `app/src/main/java/io/xpipe/app/beacon/mcp/HttpStreamableServerTransportProvider.java` — lines 194, 343
  - `app/src/main/java/io/xpipe/app/beacon/impl/ShellExecExchangeImpl.java` — line 20
  - `app/src/main/java/io/xpipe/app/prefs/AppPrefs.java` — lines 413–414
- **CWE:** CWE-942 (Overly Permissive CORS Policy), CWE-352 (CSRF)
- **Verification:** Confirmed - Wildcard CORS *, auth disableable via preference.
- **Non-default prerequisite (for unauthenticated RCE):** Requires both `enableHttpApi` (default disabled) and `disableApiAuthentication` (non-default/insecure).
- **CVSS v4.0:** 9.0 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` *(worst-case assumes the HTTP API is enabled and API authentication is disabled; wildcard CORS remains a concern even when auth is enabled)*

**Description:**  
The Beacon HTTP API and MCP server set `Access-Control-Allow-Origin: *` on every response, permitting any website to make cross-origin requests to the local API:

```java
// AppBeaconServer.java:188
exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
exchange.getResponseHeaders().add("Access-Control-Allow-Credentials", "true");
exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "*");
```

Authentication can be fully disabled via the `disableApiAuthentication` preference. When disabled, **any website the user visits** can:
1. POST to `http://127.0.0.1:<port>/shell/exec` → execute arbitrary OS commands
2. POST to `/fs/read` / `/fs/write` → read/write arbitrary files
3. POST to `/secret/decrypt` → decrypt stored credentials
4. POST to `/connection/add` → add malicious connection entries

Even with auth enabled, the wildcard CORS header is unsafe — a malicious site can probe for the API and attempt token exfiltration.

**Impact:**  
Remote code execution on the user's machine (and all connected remote systems) by visiting a malicious webpage. This is the highest-severity finding because it requires zero privilege — just a browser visit.

**Remediation:**
- Replace `Access-Control-Allow-Origin: *` with an explicit allowlist (e.g., `http://localhost:<port>` only).
- Remove `Access-Control-Allow-Credentials: true` (incompatible with wildcard origin per spec, but some browsers are lenient).
- Consider adding a CSRF token mechanism for non-Bearer-token requests.
- Add strong warnings or remove the `disableApiAuthentication` option entirely. If retained, scope it to specific endpoints rather than a global bypass.
- Add `SameSite` and anti-CSRF protections.


---

### Task 17 — No Signed Commit/Tag Verification for Cloned Git Repositories
- **Severity:** MEDIUM
- **Category:** Integrity / Supply Chain
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 135–141
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 109–116
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - No GPG signature verification after clone.
- **CVSS v4.0:** 9.0 (Critical) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
After cloning a Git repository, XPipe does not verify that commits or tags are signed by a trusted key. Any commit — even unsigned or signed by an untrusted key — is accepted without validation:

```java
// ScriptCollectionSource.java:138–140
if (Files.exists(getLocalPath())) {
    ProcessControlProvider.get().pullRepository(getLocalPath());
} else {
    ProcessControlProvider.get().cloneRepository(url, getLocalPath());
}
// Content is used immediately without integrity checks
```

A compromised repository (compromised server, MITM attacker, or rogue contributor with push access) can inject arbitrary code into cloned scripts or resources without detection.

**Impact:**  
- Scripts loaded from repositories can execute arbitrary commands if repository is compromised
- System icons/resources can be poisoned
- No audit trail of which commits were actually used

**Remediation:**
- After cloning/pulling, verify that the checked-out commit is signed with an expected GPG key:
  ```bash
  git verify-commit HEAD
  git config user.signingkey <EXPECTED_GPG_KEY>
  ```
- Alternatively, pin to a specific signed tag and verify its signature:
  ```bash
  git checkout tags/<VERSION> -b verify
  git verify-tag <VERSION>
  ```
- Store trusted GPG public keys in XPipe configuration and validate during clone/pull.
- Add UI warnings if commits are unsigned or signed by unknown keys.


---

### Task 18 — Unsafeguarded `curl | sh` Installer Execution in Prompt Installers
- **Severity:** LOW
- **Category:** Supply Chain / Integrity
- **Files:**
  - `app/src/main/java/io/xpipe/app/terminal/StarshipTerminalPrompt.java` — line 137
  - `app/src/main/java/io/xpipe/app/terminal/OhMyPoshTerminalPrompt.java` — line 170
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - curl pipe sh / curl pipe bash installation pattern.
- **CVSS v4.0:** 8.9 (High) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

**Description:**  
On non-Windows systems, prompt installers execute remote shell scripts directly via pipelines:

```java
// app/src/main/java/io/xpipe/app/terminal/StarshipTerminalPrompt.java
            sc.command("curl -sS https://starship.rs/install.sh | sh /dev/stdin -y --bin-dir \"" + dir + "\"")
                    .execute();
```

```java
// app/src/main/java/io/xpipe/app/terminal/OhMyPoshTerminalPrompt.java
            sc.command("curl -s https://ohmyposh.dev/install.sh | bash -s -- -d \"" + dir + "\" -t \"" + configDir
                            + "\"")
                    .execute();
```

No signature/checksum verification or pinned artifact validation is performed before execution.

**Impact:**  
Any compromise in the script distribution chain (DNS/TLS interception in weakened environments, upstream compromise, mirror compromise) can result in arbitrary code execution during installation.

**Remediation:**
- Prefer downloading versioned release artifacts and verifying checksums/signatures before execution.
- Pin expected release metadata and fail closed on mismatch.


---

### Task 19 — Jackson Polymorphic Deserialization Without PolymorphicTypeValidator
- **Severity:** MEDIUM
- **Category:** Deserialization
- **Files:**
  - `core/src/main/java/io/xpipe/core/JacksonMapper.java` — line 38
  - 13+ interfaces with `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)`:
    - `app/src/main/java/io/xpipe/app/ext/DataStore.java`
    - `app/src/main/java/io/xpipe/app/pwman/PasswordManager.java`
    - `app/src/main/java/io/xpipe/app/secret/SecretRetrievalStrategy.java`
    - `beacon/src/main/java/io/xpipe/beacon/BeaconAuthMethod.java`
    - `beacon/src/main/java/io/xpipe/beacon/BeaconClientInformation.java`
    - `core/src/main/java/io/xpipe/core/SecretValue.java`
    - _(and 7+ more)_
  - `app/src/main/java/io/xpipe/app/beacon/impl/ConnectionAddExchangeImpl.java`
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Verification:** Confirmed - No PolymorphicTypeValidator configured; FAIL_ON_INVALID_SUBTYPE disabled; 20+ interfaces use @JsonTypeInfo Id.NAME with dynamic registerSubtypes() registry and no type allow-list.
- **Non-default prerequisite (for remote API delivery):** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 8.8 (High) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes the HTTP API is enabled and the attacker has API access)*

**Description:**  
`DeserializationFeature.FAIL_ON_INVALID_SUBTYPE` is disabled globally. Multiple interfaces use `@JsonTypeInfo` without `@JsonSubTypes`, relying on runtime `registerSubtypes()` calls. No `PolymorphicTypeValidator` is configured on the `ObjectMapper`. The `/connection/add` API endpoint deserializes arbitrary JSON directly into `DataStore` subtypes:

```java
// app/src/main/java/io/xpipe/app/beacon/impl/ConnectionAddExchangeImpl.java
var store = JacksonMapper.getDefault().treeToValue(msg.getData(), DataStore.class);
```

**Impact:**  
If an attacker can submit crafted JSON (via the API or by modifying imported connection files), they may attempt to instantiate unexpected subtypes. While Jackson's name-based typing is safer than `JAVA_CLASS`, the lack of a type validator combined with a large dynamic subtype registry **increases deserialization attack surface** even though a direct RCE gadget path is not demonstrated here.

**Remediation:**
- Enable `FAIL_ON_INVALID_SUBTYPE`.
- Configure a `BasicPolymorphicTypeValidator` that restricts allowed base types and subtypes to the `io.xpipe` package.
- Audit all `registerSubtypes()` calls to ensure only expected classes are registered.


---

### Task 20 — Cloned/Pulled Repository Content Not Validated Before Use
- **Severity:** HIGH
- **Category:** Integrity / Code Injection
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 135–141, 173–219
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 109–116
- **CWE:** CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code), CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Verification:** Confirmed - Scripts loaded from cloned repos by file extension only.
- **CVSS v4.0:** 8.8 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
After cloning a Git repository, scripts and resources are immediately used without validation:

```java
// ScriptCollectionSource.java:173–174 — scripts are executed directly
var entry = ScriptCollectionSourceEntry.builder()
    .name(name)
    .source(ScriptCollectionSource.this)
    .dialect(dialect.get())
    .localFile(file)  // File from potentially-malicious repository
    .build();
```

Later, when a user executes a script, the file contents are run as shell commands with no safety checks.

**Impact:**  
A compromised repository or MITM attacker can inject shell scripts that:
- Execute arbitrary commands on connected systems
- Exfiltrate stored credentials
- Modify connection settings
- Install backdoors

**Remediation:**
- Validate repository integrity before use:
  - Verify GPG signatures on commits/tags (Task 17).
  - Verify specific file checksums from a trusted manifest.
  - Check repository owner/maintainer against an allowlist.
- Sandbox script execution:
  - Execute scripts in a limited environment with restricted permissions.
  - Use a scripting language sandbox if possible.
- Warn users that scripts are from external repositories:
  - Show repository URL and commit hash before first execution.
  - Require explicit user confirmation for first-time repository scripts.
- Implement an audit log of all executed repository scripts.


---

### Task 21 — No Version Pinning or Update Strategy for Git Repositories
- **Severity:** MEDIUM
- **Category:** Supply Chain / Version Management
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 103–141
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 100–125
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Verification:** Confirmed - No version/commit pinning; only URL and remote stored.
- **CVSS v4.0:** 8.8 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
When cloning a Git repository, the `prepare()` method checks out the default branch (usually `master` or `main`) without any version pinning or validation:

```java
// ScriptCollectionSource.java:140
ProcessControlProvider.get().cloneRepository(url, getLocalPath());
```

This means:
- Every clone gets the HEAD of the default branch, which may have changed since the user added the repository to their config.
- A malicious maintainer can push breaking changes or malicious code to the default branch and it will be automatically pulled.
- No audit trail of which version was actually used at any given time.

**Impact:**  
- Scripts can suddenly change or become malicious without user control.
- Automation environments using XPipe for scripts become unstable.
- Supply-chain attack surface: maintainer is trusted implicitly for all future commits.

**Remediation:**
- Allow users to pin repositories to a specific branch, tag, or commit:
  ```
  URL: https://github.com/org/repo.git
  Version: main | v1.0.0 | abc123def (commit hash)
  ```
- Prefer tags over branches for stability:
  ```java
  git clone --branch v1.0.0 --single-branch <url>
  ```
- Store the checked-out commit hash in XPipe config for audit purposes:
  ```
  CheckedOutCommit: abc123def456...
  CheckedOutDate: 2025-02-21T10:30:00Z
  ```
- Allow explicit "update to latest" operations that log/alert the user about version changes.
- Restrict automatic updates to patch versions only (e.g., `v1.0.*`) if auto-update is desired.


---

### Task 22 — Timing-Vulnerable Token Comparison (String.equals)
- **Severity:** LOW
- **Category:** Authentication
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — line 58
  - `app/src/main/java/io/xpipe/app/beacon/impl/HandshakeExchangeImpl.java` — lines 45, 50
  - `app/src/main/java/io/xpipe/app/beacon/mcp/AppMcpServer.java` — lines 157–158
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Verification:** Confirmed - String.equals for token comparison; timing-oracle risk.
- **Hardening note:** Practical token-extraction via timing over loopback is unlikely in most real environments; treat as defense-in-depth.
- **CVSS v4.0:** 8.7 (High) — `CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` *(worst-case scoring; recommended as hardening)*

**Description:**  
All authentication token and secret comparisons use `String.equals()`, which short-circuits on the first non-matching character. Over a local loopback connection (where network jitter is negligible), this leaks information about correct token prefixes.

```java
// BeaconRequestHandler.java:58
.filter(s -> s.getToken().equals(token))

// HandshakeExchangeImpl.java:45
return AppBeaconServer.get().getLocalAuthSecret().equals(c);

// HandshakeExchangeImpl.java:50
return AppPrefs.get().apiKey().get().equals(c);
```

**Impact:**  
This introduces a **potential side-channel risk** for local attackers. Practical exploitation depends on timing noise, token length, and request constraints; however, constant-time comparison is still the correct defensive pattern for authentication secrets.

**Remediation:**
- Replace all security-sensitive string comparisons with `MessageDigest.isEqual(a.getBytes(), b.getBytes())` which runs in constant time.
- Note: `TweetNaClHelper.java` already implements constant-time comparison — reuse that pattern.


---

### Task 23 — Updater Executes Downloaded Installers Without Signature/Checksum Verification
- **Severity:** HIGH
- **Category:** Supply Chain / Integrity
- **Files:**
  - `app/src/main/java/io/xpipe/app/update/AppDownloads.java` — lines 27–47
  - `app/src/main/java/io/xpipe/app/update/AppInstaller.java` — lines 143–236
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - No checksum/signature verification for downloaded updates.
- **CVSS v4.0:** 8.7 (High) — `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
Installers are downloaded and executed/installed (including privileged flows) without explicit cryptographic verification (signature or pinned checksum) in application logic.

**Impact:**  
Any compromise in the release distribution chain can result in installation of tampered binaries.

**Remediation:**
- Verify release signatures/checksums prior to install.
- Pin expected signer identity and fail closed on mismatch.
- Record and audit installer digest before execution.


---

### Task 24 — No Expiration/Reaping Policy for Beacon Session Tokens
- **Severity:** MEDIUM
- **Category:** Authentication / Session Management
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/impl/HandshakeExchangeImpl.java` — lines 31–33
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — lines 103–105
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **Verification:** Confirmed - No TTL or reaper for beacon sessions.
- **CVSS v4.0:** 8.6 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
Session tokens are generated and added, but no TTL, inactivity timeout, or periodic reaping is enforced.

**Impact:**  
Long-lived tokens increase replay window and attack persistence for local attackers who recover a token.

**Remediation:**
- Add token expiration + idle timeout.
- Revoke old sessions on restart/significant auth events.
- Expose explicit session revocation endpoint for local clients.


---

### Task 25 — Beacon Auth File Permissions Not Restricted on Windows
- **Severity:** MEDIUM
- **Category:** Local Privilege Escalation
- **File:** `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — lines 128–132
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Verification:** Confirmed - Auth file permissions rw-rw---- (POSIX only); should be rw-------.
- **CVSS v4.0:** 8.6 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The `beacon-auth` file containing the local authentication secret has POSIX `rw-rw----` permissions set on Linux/macOS, but on Windows it inherits default ACLs from the parent directory and no explicit ACL hardening is applied:

```java
Files.writeString(file, id);
if (OsType.ofLocal() != OsType.WINDOWS) {
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw----"));
}
// Windows: no ACL restriction applied
```

**Impact:**  
On multi-user Windows systems with permissive inherited ACLs, another local user may be able to read the auth secret and gain API access (shell execution, file I/O, secret decryption).

**Remediation:**
- On Windows, set restrictive ACLs using `java.nio.file.attribute.AclFileAttributeView` to grant access only to the current user.
- Consider also tightening the Linux permissions to `rw-------` (owner-only).


---

### Task 26 — SSH Agent Socket Used Without Ownership or Permissions Validation
- **Severity:** HIGH
- **Category:** SSH Agent Security / Local Privilege
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java`
  - `app/src/main/java/io/xpipe/app/prefs/AppPrefs.java` — `sshAgentSocket()` property
- **CWE:** CWE-59 (Improper Link Resolution Before File Access), CWE-732 (Incorrect Permission Assignment)
- **Verification:** Confirmed - SSH_AUTH_SOCK passed to ssh-add with no ownership/permission validation.
- **CVSS v4.0:** 8.6 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The SSH agent socket path can come from preferences and is forwarded into agent checks without validating ownership, type, or permissions.

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/CustomAgentStrategy.java
            SshIdentityStateManager.prepareLocalCustomAgent(
                    parent, AppPrefs.get().sshAgentSocket().getValue());
```

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java
        try (var c = sc.command(CommandBuilder.of().add("ssh-add", "-l").fixedEnvironment("SSH_AUTH_SOCK", authSock))
                .start()) {
            var r = c.readStdoutAndStderr();
```

A malicious path (e.g., a regular file disguised as a socket, a symlink to another socket, or a socket owned by another user) is silently accepted. An attacker who can write to the socket path before XPipe starts can intercept all SSH authentication requests.

**Impact:**  
SSH private key operations routed through a hijacked socket expose the key agent to an attacker-controlled process, enabling authentication as that user on any connected system.

**Remediation:**
- Validate the socket path before use: verify it is a UNIX socket (`Files.getAttribute(path, "unix:isSocket")`), owned by the current user, and has `0600` or `0700` permissions.
- On Windows, verify the named pipe ACL before connecting.
- Reject paths that are symlinks (`Files.isSymbolicLink(path)`) unless the target also passes validation.


### Task 27 — `sshd_config` Missing `PermitRootLogin no`
- **Severity:** HIGH
- **Category:** SSH Server Hardening
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd_config template
- **CWE:** CWE-284 (Improper Access Control)
- **Verification:** Confirmed - No PermitRootLogin no in sshd_config template.
- **CVSS v4.0:** 8.6 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The generated `sshd_config` template does not include `PermitRootLogin no`. On systems where the bridge runs as root (e.g., certain container/service configurations), this omission permits root authentication through the bridge, bypassing the principle of least privilege:

```
# Current sshd_config template — no PermitRootLogin directive
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile "..."
StrictModes no
```

**Impact:**  
If XPipe runs as root or is started in a privileged context, the bridge `sshd` permits root login, overriding OS-level root SSH restrictions. Combined with any other weakness (key theft, injection), the attacker gains root on the bridge host.

**Remediation:**
- Add `PermitRootLogin no` to the sshd_config template unconditionally.
- Add `AllowUsers <current_user>` to further restrict authentication targets.


---

### Task 28 — `sshd_config` Missing `AllowUsers` Directive
- **Severity:** MEDIUM
- **Category:** SSH Server Hardening / Access Control
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd_config template
- **CWE:** CWE-284 (Improper Access Control)
- **Verification:** Confirmed - No AllowUsers directive in sshd_config template.
- **CVSS v4.0:** 8.6 (High) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

**Description:**  
The bridge `sshd_config` does not include an `AllowUsers` directive restricting authentication to only the current user. On multi-user systems:

(See the `sshd_config` template snippet in Task 101; it does not include `AllowUsers`.)

Any user with access to the bridge's `authorized_keys` format and the correct port could attempt to authenticate. While `AuthorizedKeysFile` is scoped to the generating user's credential, the absence of `AllowUsers` relies entirely on OpenSSH's default behavior.

**Impact:**  
Defence-in-depth weakened: if the `AuthorizedKeysFile` path is compromised or the key material is accessible to another user, `AllowUsers` would prevent that user from authenticating regardless.

**Remediation:**
- Determine the current OS username at bridge startup and inject it:
  ```java
  var user = System.getProperty("user.name");
  templateBuilder.add("AllowUsers", user);
  ```


---

### Task 29 — Command Injection via Crafted Filenames (FileOpener)
- **Severity:** MEDIUM
- **Category:** Command Injection
- **File:** `app/src/main/java/io/xpipe/app/util/FileOpener.java`
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - String concatenation for start, xdg-open, open; only PowerShell branch safe.
- **CVSS v4.0:** 8.5 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Local file paths are passed to OS open commands with only double-quote wrapping:

```java
pc.executeSimpleCommand("start \"\" \"" + localFile + "\"");
pc.executeSimpleCommand("xdg-open \"" + localFile + "\"");
pc.executeSimpleCommand("open \"" + localFile + "\"");
```

Filenames containing `"` (or `$(...)` on bash, `"&` on CMD) can break out of the quotes and inject commands.

**Impact:**  
A malicious file on a remote server with a crafted filename could execute arbitrary commands on the local machine when the user opens it through XPipe's file browser.

**Remediation:**
- Use `ProcessBuilder` with separate arguments instead of string concatenation through a shell.
- At minimum, escape shell metacharacters via the shell dialect's `quoteArgument()` or `literalArgument()` methods.


---

### Task 30 — Secret Decryption Oracle via /secret/decrypt API Endpoint
- **Severity:** LOW
- **Category:** API Security / Credential Exposure
- **File:** `app/src/main/java/io/xpipe/app/beacon/impl/SecretDecryptExchangeImpl.java`
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Verification:** Confirmed - Returns plaintext secret in HTTP response body.
- **Non-default prerequisite (for unauthenticated oracle):** Requires both `enableHttpApi` (default disabled) and `disableApiAuthentication` (Task 16) to be enabled.
- **CVSS v4.0:** 8.4 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes the HTTP API is enabled and API auth is disabled; otherwise this remains an authenticated plaintext-secret exposure endpoint)*

**Description:**  
The `/secret/decrypt` endpoint accepts any encrypted JSON blob and returns the plaintext string:

```java
public Object handle(HttpExchange exchange, Request msg) throws IOException, BeaconClientException {
    var secret = DataStorageSecret.deserialize(msg.getEncrypted());
    return Response.builder().decrypted(new String(secret.getSecret())).build();
}
```

When authentication is disabled (Task 16), this is an unauthenticated decryption oracle for every stored credential.

**Impact:**  
Extraction of all stored passwords, API keys, and secrets in plaintext via a single unauthenticated API call.

**Remediation:**
- This endpoint should **never** be accessible without authentication.
- Consider requiring additional confirmation (e.g., user prompt) before decrypting secrets via API.
- Add rate limiting and audit logging.
- Evaluate whether this endpoint is necessary at all — can consumers use the secret directly rather than decrypting it?


---

### Task 31 — Credential Material Written to Disk in Temporary Connection Config Files
- **Severity:** HIGH
- **Category:** Secret Handling / Information Disclosure
- **Files:**
  - `app/src/main/java/io/xpipe/app/vnc/RemoteViewerVncClient.java` — lines 40–51
  - `app/src/main/java/io/xpipe/app/rdp/ExternalRdpClient.java` — lines 90–96
  - `app/src/main/java/io/xpipe/app/util/RemminaHelper.java` — lines 63–93, 100–126
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-922 (Insecure Storage of Sensitive Information)
- **Verification:** Confirmed - Credentials written to temp files on disk.
- **CVSS v4.0:** 8.3 (High) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**  
Multiple external-client integrations write connection configuration files into a local temp directory, and these files may contain credential material:

- `RemoteViewerVncClient` writes a `.vv` file that includes a plaintext `password=<secret>` line when a password is available:

```java
vv += "password=" + pass.get().getSecretValue() + "\n";
Files.writeString(file, content);
```

- `ExternalRdpClient.writeRdpConfigFile()` writes a `.rdp` file to disk based on `RdpConfig.toString()`.
- `RemminaHelper` writes `.remmina` files that include a `password=%s` field.

While the VNC config is scheduled for deletion after 5 seconds, deletion is best-effort and can fail; additionally, any config file written to disk can be read by other processes running as the user (malware, debuggers, backup/indexer tools), remain on disk after crashes, and be captured by EDR/telemetry.

**Impact:**  
Credentials (or credential-like material) can be exposed locally via temp-file scraping, crash artifacts, backups, or delayed cleanup. This increases the blast radius of any local compromise and weakens expectations that credentials are kept in memory/OS keychain only.

**Remediation:**
- Prefer not writing passwords into files at all; use interactive prompting in the target client, OS credential stores, or secure IPC mechanisms.
- If a file is unavoidable:
  - Generate an unpredictable filename (e.g., `Files.createTempFile`) and avoid deterministic naming based on connection title.
  - Create the file with restrictive permissions (e.g., `0600` on POSIX) and avoid overwriting existing files.
  - Ensure cleanup on process exit and on failure paths (best-effort delayed deletion is not sufficient).
  - Consider writing a password-less config file and passing the secret via a safer channel when supported.


---

### Task 32 — AskpassExchange Allows Authenticated API Clients to Display Arbitrary Credential Dialogs
- **Severity:** MEDIUM
- **Category:** UI Phishing / Privilege Abuse
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/impl/AskpassExchangeImpl.java` — lines 50–55
  - `beacon/src/main/java/io/xpipe/beacon/api/AskpassExchange.java` — line 16
- **CWE:** CWE-451 (User Interface (UI) Misrepresentation of Critical Information)
- **Verification:** Confirmed - Shows arbitrary prompt text when request == null.
- **CVSS v4.0:** 8.3 (High) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**  
When the `AskpassExchange` `/askpass` endpoint receives a request where `request` and `secretId` are both `null`, it bypasses the `SecretManager` progress lookup and directly invokes `AskpassAlert.queryRaw()` with the caller-supplied `prompt` string:

```java
if (msg.getRequest() == null) {
    var r = AskpassAlert.queryRaw(prompt, null, true);
    return Response.builder()
        .value(r.getState() == SecretQueryState.NORMAL ? r.getSecret() : InPlaceSecretValue.of(""))
        .build();
}
```

The endpoint has `requiresEnabledApi()` returning `false` (accessible even when the API is disabled) and `acceptInShutdown()` returning `true` (accessible during shutdown). Any holder of a valid Beacon API token can pop up a native-looking credential input dialog with arbitrary attacker-controlled text and silently receive the entered credentials.

**Impact:**  
An authenticated third-party application using the XPipe Beacon API can display a spoofed authentication prompt (e.g., `"Enter your SSH passphrase for server.example.com:"`) to the user and capture whatever credentials the user types. The user has no way to distinguish the dialog from a legitimate XPipe credential prompt. Combined with any token theft or a rogue application with token access, this enables silent credential harvesting.

**Remediation:**
- Enforce that `/askpass` requests without an active `SecretManager` progress entry (i.e., `request == null`) are rejected with a `BeaconClientException` rather than showing an uncorrelated dialog.
- Tie every askpass dialog invocation to a registered, application-initiated credential request that can be traced back to a legitimate shell session.
- Apply rate-limiting to the `/askpass` endpoint to limit brute-force prompt attempts.


---

### Task 33 — `xpipe://action` Deep Links Execute Without User Confirmation
- **Severity:** MEDIUM
- **Category:** Authorization / UX Security Boundary
- **Files:**
  - `app/src/main/java/io/xpipe/app/core/AppOpenArguments.java` — lines 45–60, 81–98
  - `app/src/main/java/io/xpipe/app/action/XPipeUrlProvider.java` — lines 13–21
  - `app/src/main/java/io/xpipe/app/action/ActionUrls.java` — lines 67–111
- **CWE:** CWE-285 (Improper Authorization), CWE-602 (Client-Side Enforcement of Server-Side Security)
- **Verification:** Confirmed - xpipe:// action dispatch via executeAsync().
- **CVSS v4.0:** 8.2 (High) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N`

**Description:**  
Launcher/open arguments are parsed into actions and executed immediately via `executeAsync()` with no explicit confirmation for deep-link sourced actions:

```java
all.forEach(launcherInput -> {
    launcherInput.executeAsync();
});
```

For `xpipe://action?...`, the URL host `action` is accepted and converted into an internal action object via `ActionUrls.parse(query)`, then executed. There is no per-action trust gate, prompt, or allowlist policy specific to external URI invocations.

**Impact:**  
If a user is tricked into opening a crafted `xpipe://action?...` link (or another local process can invoke the custom protocol handler), XPipe can execute internal actions against existing stores without an explicit consent step. Depending on installed actions and referenced stores, this can trigger sensitive workflows (connections, command sessions, file operations) unintentionally.

**Remediation:**
- Add a mandatory confirmation dialog for externally sourced deep-link actions, displaying action type and targets.
- Restrict deep-link execution to a minimal allowlist of safe/read-only actions.
- Require an HMAC/signature or one-time nonce for high-risk deep links.
- Add telemetry/audit logging for protocol-triggered action execution.


---

### Task 34 — Password Passed as Plain Command-Line Argument to FreeRdp (`/p:`)
- **Severity:** HIGH
- **Category:** Credential Exposure / Command Injection
- **File:** `app/src/main/java/io/xpipe/app/rdp/FreeRdpClient.java` — lines 51–53
- **CWE:** CWE-214 (Invocation of Process Using Visible Sensitive Information), CWE-116 (Improper Encoding or Escaping of Output)
- **Verification:** Confirmed - Password passed as /p: on command line; .sensitive() does not prevent /proc exposure.
- **CVSS v4.0:** 8.2 (High) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
When a password is available, it is placed on the xfreerdp command line with only a minimal single-quote escaping step:

```java
if (configuration.getPassword() != null) {
    var escapedPw = configuration.getPassword().getSecretValue().replaceAll("'", "\\\\'");
    b.add("/p:'" + escapedPw + "'");
}
```

Two weaknesses are present:

1. **Process listing exposure**: The password appears verbatim in `ps aux`, `top`, `/proc/<pid>/cmdline`, EDR telemetry, and shell history until the process terminates.
2. **Broken shell escaping**: In most POSIX shells there is no escape for `'` inside single-quoted strings; `\'` closes the literal and then produces a backslash-quote sequence, meaning passwords containing `'` either corrupt the argument or produce an injection vector.

**Impact:**  
- Any local user who can read `/proc` (everyone on Linux by default) can extract the RDP password during the session-launch window.
- EDR/SIEM tools logging process arguments will record credentials permanently.
- Passwords containing single quotes may silently fail to authenticate or, in edge cases involving shell interpretation, inject commands.

**Remediation:**
- Write all connection parameters including the password into the `.rdp` config file and pass only the file path to xfreerdp. Microsoft's `.rdp` spec supports a `password 51:b:` (hashed) field; FreeRdp also supports plaintext `password:s:` when the file is owner-readable-only.
- If command-line passing is unavoidable use `ProcessBuilder` with discrete `List<String>` arguments (no shell interpolation) to at least prevent shell injection, and document the process-listing risk.
- Add an `IdentitiesOnly`-style opt-out preference that forces interactive password entry instead of passing the credential automatically.


---

### Task 35 — `FixedSizeInputStream` Violates EOF Contract and Can Corrupt Data
- **Severity:** MEDIUM
- **Category:** Logic Bug / Data Integrity
- **File:** `app/src/main/java/io/xpipe/app/util/FixedSizeInputStream.java` — lines 20–27
- **CWE:** CWE-252 (Unchecked Return Value) / CWE-440 (Expected Behavior Violation)
- **Verification:** Confirmed - Returns 0 on EOF instead of -1; internal count incremented incorrectly.
- **CVSS v4.0:** 8.2 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
When the wrapped stream returns EOF (`-1`), `FixedSizeInputStream.read()` returns `0` instead of `-1` and still increments `count`:

```java
var read = in.read();
count++;
if (read == -1) {
  return 0;
}
```

This breaks `InputStream` semantics and can inject null bytes while masking premature EOF.

**Impact:**  
Consumers may accept corrupted content (zero-byte padding) instead of detecting truncation, which can silently alter edited file contents and produce inconsistent writes.

**Remediation:**
- Return `-1` immediately when wrapped stream returns EOF.
- Increment `count` only for successfully read bytes.


### Task 36 — FilterComp Paste Intercept Dispatches `xpipe://` URLs Without Confirmation
- **Severity:** MEDIUM
- **Category:** UI Injection / Deep-Link Abuse
- **Files:**
  - `app/src/main/java/io/xpipe/app/comp/base/FilterComp.java` — lines 78–82
  - `app/src/main/java/io/xpipe/app/core/AppOpenArguments.java` — line 67
- **CWE:** CWE-20 (Improper Input Validation), CWE-601 (URL Redirection to Untrusted Site — analogous for local protocol handling)
- **Verification:** Confirmed - Clipboard paste dispatches xpipe:// URLs.
- **CVSS v4.0:** 8.1 (High) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N`

**Description:**  
The UI search/filter text field in `FilterComp` silently intercepts pasted text that begins with `xpipe://` and dispatches it directly to `AppOpenArguments.handle()`, which calls `launcherInput.executeAsync()` with no confirmation gate:

```java
filter.textProperty().addListener((observable, oldValue, n) -> {
    // Handle pasted xpipe URLs
    if (n != null && n.startsWith("xpipe://")) {
        AppOpenArguments.handle(List.of(n));
        filter.setText(null);
        return;
    }
    ...
});
```

A pastejacking attack (e.g., malicious web page using `clipboard.writeText()` on hover/click) can silently replace the user's clipboard with a crafted `xpipe://action?...` URL. When the user pastes into XPipe's search box — a very common action — the action executes without any visible indication or consent dialog.

**Impact:**  
Social engineering combined with clipboard poisoning allows unauthenticated local action execution through the user's UI. Any action registered in `ActionUrls` (including connection management and configuration actions) is reachable. The text box content is immediately cleared (`filter.setText(null)`), making the attack invisible to the user.

**Remediation:**
- Require explicit user confirmation before executing any `xpipe://` URL obtained from paste input.
- Display the URL and action description in a confirmation dialog, mirroring Task 33 remediation for protocol-handler dispatch.
- Alternatively, restrict the paste-dispatch path to only specific safe action types (e.g., navigation-only actions).


---

### Task 37 — macOS osascript Injection via Notification Strings
- **Severity:** MEDIUM
- **Category:** Command Injection
- **File:** `app/src/main/java/io/xpipe/app/core/AppTrayIcon.java` — lines 106–112
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - AppleScript injection via String.format; no escaping.
- **CVSS v4.0:** 7.4 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Notification messages are interpolated into an AppleScript command with only double-quote wrapping, no escaping:

```java
String execute = String.format(
    "display notification \"%s\" with title \"%s\" subtitle \"%s\"",
    message != null ? message : "",
    title != null ? title : "",
    subTitle != null ? subTitle : "");
Runtime.getRuntime().exec(new String[] {"osascript", "-e", execute});
```

A message containing `"` followed by AppleScript would escape the string and execute arbitrary AppleScript commands.

**Impact:**  
If any user-influenced data flows into error messages or notification text (e.g., a remote hostname, connection name, or error string from a remote server), arbitrary AppleScript execution is possible.

**Remediation:**
- Escape double quotes in all interpolated values: `value.replace("\"", "\\\"")`.
- Better: use `-e 'display notification' -e` with separate arguments to avoid string interpolation entirely.
- Best: use the Java `java.awt.TrayIcon.displayMessage()` API instead of shelling out to osascript.


---

### Task 38 — PowerShell Injection via Windows Credential Manager Keys
- **Severity:** MEDIUM
- **Category:** Command Injection
- **File:** `app/src/main/java/io/xpipe/app/pwman/WindowsCredentialManager.java` — lines 102–106
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - Only double-quote replacement; no $() or backtick protection.
- **CVSS v4.0:** 7.4 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Credential names from the password manager are injected into PowerShell commands with only `"` escaped to `` `" ``:

```java
.command("[CredManager.Credential]::GetUserName(\"" + key.replaceAll("\"", "`\"") + "\")")
```

PowerShell sub-expressions `$()`, backtick sequences, and variable expansion `$env:...` are not sanitized.

**Impact:**  
A crafted credential name (e.g., from an imported connection config) could execute arbitrary PowerShell when the credential is looked up.

**Remediation:**
- Use single-quoted PowerShell strings (which don't interpolate) and escape embedded single quotes: `value.replace("'", "''")`.
- Alternatively, pass values via PowerShell `-EncodedCommand` with Base64 or via stdin to avoid shell interpretation entirely.


---

### Task 39 — Command Injection via Password Manager Key Values
- **Severity:** MEDIUM
- **Category:** Command Injection
- **Files:**
  - `app/src/main/java/io/xpipe/app/pwman/PasswordManagerCommand.java` — line 108
  - `app/src/main/java/io/xpipe/app/prefs/ExternalApplicationHelper.java` — lines 17–24
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - Naive string substitution for shell commands.
- **CVSS v4.0:** 7.4 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
User-provided password manager keys are substituted into a user-defined command template via `ExternalApplicationHelper.replaceVariableArgument()`. This method only wraps values in double quotes when they contain spaces — it does **not** escape shell metacharacters like `;`, `|`, `$()`, or backticks:

```java
var cmd = ExternalApplicationHelper.replaceVariableArgument(script.getValue(), "KEY", key);
var secret = retrieveWithCommand(cmd);
```

**Impact:**  
A password manager key containing `"; rm -rf /; echo "` would inject a destructive command into the shell execution.

**Remediation:**
- Always shell-quote the substituted value using the shell dialect's `literalArgument()` method.
- Validate key names against a strict allowlist pattern (e.g., alphanumeric + limited punctuation).


---

### Task 40 — dbus-send Command Injection via Remote File Paths
- **Severity:** MEDIUM
- **Category:** Command Injection
- **File:** `app/src/main/java/io/xpipe/app/util/DesktopHelper.java` — line 193
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - dbus-send with interpolated path; command injection vector.
- **CVSS v4.0:** 7.4 (High) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
A remote file path is interpolated directly into a `dbus-send` shell command string without shell quoting:

```java
var dbus = String.format("""
    dbus-send ... %s array:string:"file://%s" string:""", action, path);
sc.executeSimpleBooleanCommand(dbus);
```

**Impact:**  
A remote file or directory with shell metacharacters in its name could inject commands when the user browses to it.

**Remediation:**
- Use `CommandBuilder` with `.addFile()` or `.addQuoted()` instead of `String.format()`.


---

### Task 41 — Command Injection via DesktopShortcuts.createMacOSShortcut
- **Severity:** MEDIUM
- **Category:** Command Injection
- **File:** `app/src/main/java/io/xpipe/app/util/DesktopShortcuts.java` — line 115
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - macOS makeFileSystemCompatible only strips /\: and null; shell metacharacters ($, backtick, ") survive into chmod/cp string-concatenated commands, enabling injection.
- **CVSS v4.0:** 7.4 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The `name` parameter is interpolated directly into a shell command string without escaping:

```java
var macExec = base + "/Contents/MacOS/" + name;
pc.executeSimpleCommand("chmod ugo+x \"" + macExec + "\"");
```

**Impact:**  
If `name` contains shell metacharacters (e.g., `"; rm -rf /; echo "`), it could lead to arbitrary command execution when creating a macOS shortcut.

**Remediation:**
- Use `CommandBuilder` to construct the command safely: `pc.command(CommandBuilder.of().add("chmod", "ugo+x").addFile(macExec)).execute();`


---

### Task 42 — `authorized_keys` File Not Enforced to Owner-Only Permissions After Bridge Write
- **Severity:** MEDIUM
- **Category:** SSH Key Security / File Permissions
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — `AuthorizedKeysFile` setup
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Verification:** Confirmed - No chmod or permission enforcement after authorized_keys generation.
- **CVSS v4.0:** 7.2 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The bridge configures `AuthorizedKeysFile` and disables `StrictModes`, but does not explicitly set secure file permissions for the keys it relies on:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
            var content = """
                          ForceCommand %s
                          PidFile "%s"
                          StrictModes no
                          SyslogFacility USER
                          LogLevel Debug3
                          Port %s
                          PasswordAuthentication no
                          HostKey "%s"
                          PubkeyAuthentication yes
                          AuthorizedKeysFile "%s"
                          """.formatted(
                            command,
                            pidFile.toString(),
                            "" + port,
                            INSTANCE.getHostKey().toString(),
                            INSTANCE.getPubIdentityKey());
```

If a local attacker can modify files under the bridge directory (misconfiguration/permissions issue), they can replace/append keys and authenticate to the bridge as the target user.

**Impact:**  
An attacker with local write access to the bridge directory can inject their SSH public key and gain authenticated access to any shell session the bridge exposes.

**Remediation:**
- After writing the `authorized_keys` file, explicitly enforce `0600` permissions on POSIX:
  ```java
  Files.setPosixFilePermissions(authKeysPath, PosixFilePermissions.fromString("rw-------"));
  ```
- Set `StrictModes yes` so sshd validates the file permissions itself.
- Ensure the parent directory is `0700` (owner-only).


---

### Task 43 — In-Memory SSH Key Handle Not Zeroed on Connection Close
- **Severity:** MEDIUM
- **Category:** Credential Lifecycle / Memory Safety
- **Files:**
  - `core/src/main/java/io/xpipe/core/InPlaceSecretValue.java`
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/InPlaceKeyStrategy.java`
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/KeyFileStrategy.java`
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Verification:** Partially confirmed - no explicit zeroing of key/passphrase buffers is visible in these code paths; Java GC does not guarantee timely overwrite.
- **CVSS v4.0:** 7.0 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**

Private key byte arrays loaded from disk into memory for direct authentication are held in `byte[]` or `String` fields of long-lived objects. When a connection is closed, those objects are dereferenced but the underlying memory is not explicitly zeroed before GC.

**Why It Matters:**

A heap dump taken after connection teardown (e.g., via `jmap`, a GC log, or OS memory forensics) may still contain recoverable private key material.

**Recommended Fix:**

Wrap key bytes in a `SecretKeySpec` or a custom `AutoCloseable` holder that zeros its internal array in `close()`. Call `close()` (ideally in a try-with-resources block) as soon as the key is no longer needed.


---

### Task 44 — Debug Logging May Expose Secrets in Request/Response Bodies
- **Severity:** LOW
- **Category:** Information Disclosure
- **Files:**
  - `beacon/src/main/java/io/xpipe/beacon/BeaconClient.java` — lines 49–51
  - `app/src/main/java/io/xpipe/app/core/AppProperties.java` — line 98
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Verification:** Confirmed - Debug logging of request/response payloads at trace level.
- **Non-default prerequisite:** Requires diagnostic mode (e.g., `io.xpipe.beacon.printMessages`) and/or dev-only configuration (e.g., `devLoginPassword` system property).
- **CVSS v4.0:** 7.0 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N` *(worst-case assumes diagnostic/dev flags are enabled)*

**Description:**  
When `io.xpipe.beacon.printMessages` is enabled, all request and response bodies — including passwords, tokens, and secret material — are printed to stdout:

```java
if (BeaconConfig.printMessages()) {
    System.out.println("Sending raw request:");
    System.out.println(content);  // May contain tokens, passwords, encrypted secrets
}
```

Additionally, `devLoginPassword` is read from a system property, making it visible in process listings.

**Impact:**  
Sensitive credentials leaked to logs, console output, or process tables.

**Remediation:**
- Redact sensitive fields (`password`, `secret`, `token`, `apiKey`) before logging.
- Remove `devLoginPassword` from system properties; use a file-based approach instead.
- Ensure debug logging is impossible to enable in production builds.


---

### Task 45 — SSH Key File Permissions Not Validated on Windows (No ACL Hardening)
- **Severity:** MEDIUM
- **Category:** Key Management / File Permissions
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/InPlaceKeyStrategy.java`
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/KeyFileStrategy.java`
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Verification:** Confirmed - No Windows ACL hardening for temporary SSH key files.
- **CVSS v4.0:** 7.0 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**

On non-Windows systems, XPipe attempts to restrict identity file permissions via `chmod`. On Windows, the same file-permission hardening path is skipped, meaning the effective access control for identity files written by the app (e.g., temp `.key` files) depends on the default ACLs of the temp directory and the user's environment.

**Why It Matters:**

Another user account or a compromised service account on the same machine can copy the private key material without any indication to the owner.

**Recommended Fix:**

After writing an SSH identity file on Windows, use Java's `AclFileAttributeView` (or `icacls` via a subprocess) to restrict the file's DACL to the current user only, mirroring the POSIX `600` behaviour.


---

### Task 46 — Temporary Connection Files Retained After Session Closes
- **Severity:** MEDIUM
- **Category:** Temporary File Security / Data Lifecycle
- **Files:**
  - `app/src/main/java/io/xpipe/app/util/LocalFileTracker.java` — `deleteOnExit()`/`reset()` tracking
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/InPlaceKeyStrategy.java` — registers local key files for cleanup
- **CWE:** CWE-377 (Insecure Temporary File), CWE-226 (Sensitive Information Uncleared Before Release)
- **Verification:** Confirmed - Temp key files use deleteOnExit; crash leaves private keys on disk.
- **CVSS v4.0:** 7.0 (High) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**  
When establishing temporary SSH tunnels or forwarding, XPipe creates temporary configuration files (socket descriptors, forwarding configs) that may not be deleted if the connection crashes or is forcefully terminated. These files may contain:
- SSH tunnel parameters
- Port forwarding rules
- Temporary credential handles

**Impact:**  
Stale sensitive configuration files accumulate on disk, increasing exposure window for filesystem-based attacks.

**Remediation:**
- Implement guaranteed cleanup using try-with-resources for all temp files
- Use temp directory shredding on app shutdown
- Log all temp file creation/deletion for audit
- Validate temp file deletion succeeded before reporting success


---

### Task 47 — Incorrect Blob Size Heuristic Uses `InputStream.available()`
- **Severity:** MEDIUM
- **Category:** Availability / Logic Bug
- **File:** `app/src/main/java/io/xpipe/app/beacon/impl/FsBlobExchangeImpl.java` — lines 16–23
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - available() then readAllBytes; unreliable size estimation.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 6.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` *(worst-case assumes the HTTP API is enabled)*

**Description:**  
Blob upload routing decisions use `exchange.getRequestBody().available()` to decide memory vs file storage. `available()` is not total stream length and often returns `0` for sockets.

```java
var size = exchange.getRequestBody().available();
if (size > 100_000_000) {
    BlobManager.get().store(id, exchange.getRequestBody());
} else {
    BlobManager.get().store(id, exchange.getRequestBody().readAllBytes());
}
```

**Impact:**  
Large uploads can be misclassified into the in-memory path and trigger memory exhaustion.

**Remediation:**
- Do not rely on `available()` for payload sizing.
- Enforce `Content-Length` limits and/or stream to file by default.
- Add hard upper bounds for blob endpoints.


---

### Task 48 — Unbounded HTTP Request Body Reads (Memory DoS)
- **Severity:** HIGH
- **Category:** Availability / Resource Exhaustion
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — lines 75–96
  - `app/src/main/java/io/xpipe/app/beacon/mcp/HttpStreamableServerTransportProvider.java` — line 268
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - readAllBytes with no size limit on request body.
- **CVSS v4.0:** 6.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

**Description:**  
Multiple HTTP handlers read full request bodies into memory with `readAllBytes()` and no explicit size limit.

```java
// app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java
                    var read = is.readAllBytes();
```

```java
// app/src/main/java/io/xpipe/app/beacon/mcp/HttpStreamableServerTransportProvider.java
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
```

**Impact:**  
An authenticated (or auth-bypassing) client can send oversized payloads and force high heap usage / OOM, degrading or crashing the local API daemon.

**Remediation:**
- Enforce strict per-endpoint max body size before buffering.
- Use bounded streaming parsers where possible.
- Return HTTP 413 for oversized payloads.


---

### Task 49 — No Timeout or Resource Limits on Git Operations
- **Severity:** MEDIUM
- **Category:** Availability / Resource Management
- **Files:**
  - `app/src/main/java/io/xpipe/app/ext/ProcessControlProvider.java` — lines 78–80
  - Git implementation (not visible in this source tree)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-674 (Uncontrolled Recursion)
- **Verification:** Confirmed - Interface has no timeout parameters, callers in ScriptCollectionSource.prepare() and SystemIconSource.refresh() invoke clone/pull with no timeout wrapper, and the closed-source implementation is unauditable.
- **CVSS v4.0:** 6.9 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

**Description:**  
The ProcessControlProvider does not expose timeout or resource-limit parameters for Git operations:

```java
public abstract void cloneRepository(String url, Path target) throws Exception;
public abstract void pullRepository(Path target) throws Exception;
```

Without explicit limits, Git operations can:
- Run indefinitely if the remote server hangs or network is slow
- Download enormous repositories (100 GB+)
- Recurse infinitely if the repository contains circular references or deeply nested submodules
- Exhaust local disk space

**Impact:**  
- DoS by providing a URL to a slow/unresponsive server or enormous repository
- Disk space exhaustion
- Resource starvation for other operations

**Remediation:**
- Add timeouts to Git operations:
  ```bash
  git clone --timeout=30 --depth=10 <url>
  ```
- Limit repository size:
  ```bash
  git clone --filter=blob:limit=100m <url>
  ```
- Set resource limits in ProcessControlProvider:
  ```java
  void cloneRepository(String url, Path target, 
      Duration timeout, long maxSizeBytes) throws Exception;
  ```
- Disable submodules by default and allow opt-in:
  ```bash
  git clone --no-recurse-submodules <url>
  ```
- Monitor disk usage during clone and cancel if threshold exceeded.


---


### Task 50 — MCP Session Lifecycle Leak (Unbounded Session Growth)
- **Severity:** LOW
- **Category:** Availability / Session Management
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/mcp/HttpStreamableServerTransportProvider.java` — lines 48, 493–504
  - `app/src/main/java/io/xpipe/app/beacon/mcp/AppMcpServer.java` — lines 40–48
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - Session removal code commented out; sessions accumulate indefinitely.
- **Non-default prerequisite:** Requires `enableMcpServer` to be enabled (default is disabled) and MCP clients to connect repeatedly.
- **CVSS v4.0:** 6.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` *(worst-case assumes MCP server is enabled and repeatedly connected to)*

**Description:**  
MCP sessions are stored in a `ConcurrentHashMap`, but on transport close they are not removed (removal line is commented). Also the keepalive cleanup scheduler is disabled by passing `null` interval.

**Impact:**  
Repeated connects/disconnects can accumulate stale sessions and increase memory/state load over time.

**Remediation:**
- Remove session entries in transport `close()` and on stream errors.
- Enable periodic stale-session cleanup with TTL.
- Add max session caps per origin/client.


---

### Task 51 — Sentry DSN Hardcoded in Build Script
- **Severity:** LOW
- **Category:** Information Disclosure
- **File:** `build.gradle` — line 270
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Verification:** Confirmed - Sentry DSN hardcoded in build script.
- **CVSS v4.0:** 6.9 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:L`

**Description:**  
The Sentry ingest URL is hardcoded in the build script:

```groovy
sentryUrl = "https://fd5f67ff10764b7e8a704bec9558c8fe@o1084459.ingest.sentry.io/6094279"
```

While Sentry DSNs are semi-public by design, exposure in source allows anyone to send garbage events to the project's Sentry instance, creating noise or consuming quota.

**Remediation:**
- Move the DSN to an environment variable or Gradle property (not committed to source).
- Configure Sentry with rate limiting and allowed-origin restrictions on the server side.


---

### Task 52 — Passphrase Not Cleared from Memory After SSH Key Unlock
- **Severity:** MEDIUM
- **Category:** Credential Lifecycle / Memory Safety
- **Files:** `app/src/main/java/io/xpipe/app/storage/DataStoreEntryRef.java`, `app/src/main/java/io/xpipe/app/prefs/`
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Verification:** Confirmed - SecretValue.getSecretValue() returns immutable String; callers (InPlaceKeyStrategy, VNC/RDP clients) bypass the safe withSecretValue() char[] pattern, leaving key material in heap.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**

When a passphrase-protected SSH identity is unlocked through the GUI prompt, the passphrase is held as a `String` (immutable in Java) or `char[]` field that is not explicitly zeroed after the key is loaded into the SSH agent or used directly. Java's garbage collector does not guarantee timely collection of sensitive objects.

**Why It Matters:**

A heap dump or memory-inspection of the JVM process can recover passphrases long after they were used, compounding the impact of a local privilege escalation or memory-disclosure vulnerability.

**Recommended Fix:**

Store the passphrase as a `char[]`, pass it to the key-loading routine, and explicitly zero the array immediately after use (`Arrays.fill(passphrase, '\0')`). Avoid converting to `String` at any intermediate step.


---

### Task 53 — Password Manager Cache Duration Allows Long-Lived Plaintext In Heap
- **Severity:** MEDIUM
- **Category:** Credential Management / Memory Lifetime
- **File:** `ext/base/src/main/java/io/xpipe/ext/base/identity/PasswordManagerIdentityStore.java`
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Verification:** Confirmed - cached credentials are stored via InternalCacheDataStore; refresh decisions are based on PasswordManager cacheDuration (seconds) and cached plaintext credentials can be returned without re-query.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
The `PasswordManagerIdentityStore` caches credentials and decides whether to refresh based on the configured PasswordManager cache duration:

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/PasswordManagerIdentityStore.java
    private boolean checkOutdatedOrRefresh() {
        var instant = getCache("lastQueried", Instant.class, null);
        if (instant != null) {
            var now = Instant.now();
            var pm = AppPrefs.get().passwordManager().getValue();
            var cacheDuration = pm != null ? pm.getCacheDuration().toSeconds() : 15;
            if (Duration.between(instant, now).toSeconds() < cacheDuration) {
                return false;
            }
        }

        return true;
    }
```

When refresh is skipped, cached plaintext credentials can be returned from the cache:

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/PasswordManagerIdentityStore.java
    private PasswordManager.CredentialResult retrieveCredentials() {
        if (!checkOutdatedOrRefresh()) {
            var credential = getCache("credential", PasswordManager.CredentialResult.class, null);
            if (credential != null) {
                return credential;
            }
        }
```

There is no maximum cache duration limit to protect against very long hold times, and there is no active eviction — the credential stays until the next cache check.

**Impact:**  
A heap dump taken during an active SSH session captures all cached credentials for all active password-manager-backed connections in plaintext.

**Remediation:**
- Enforce a hard maximum cache duration (e.g., 15 seconds) regardless of provider setting.
- Implement active expiry: schedule a task to zero the cached credential at expiry rather than relying on the next read to expire it.
- Store cache entries as `SoftReference<CredentialResult>` so GC can jettison them under memory pressure.


---

### Task 54 — Password Manager Credential Cache Not Securely Wiped After Expiry
- **Severity:** MEDIUM
- **Category:** Credential Management / Memory Security
- **File:** `ext/base/src/main/java/io/xpipe/ext/base/identity/PasswordManagerIdentityStore.java`
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory), CWE-401 (Missing Release of Memory After Effective Lifetime)
- **Verification:** Confirmed - Expired cache overwritten; old CredentialResult left for GC with no zeroing.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
Credentials retrieved from the password manager are cached using `setCache("credential", r)` with a duration-based expiry. When the cache entry expires, the `CredentialResult` object is simply discarded via normal GC — it is not explicitly zeroed or cleared:

```java
var r = AppPrefs.get().passwordManager().getValue().retrieveCredentials(key);
setCache("lastQueried", Instant.now());
setCache("credential", r);   // CredentialResult holds username + plaintext password as String
return r;
// On expiry: entry removed from cache map, but String content remains in heap
// until GC — could be minutes to hours on a healthy JVM
```

**Impact:**  
Expired credential material (usernames and plaintext passwords for SSH connections) lingers in JVM heap memory after the cache TTL elapses. A heap dump taken at any point within that window reveals the credentials.

**Remediation:**
- Use `char[]` instead of `String` for password fields and explicitly zero them on expiry:
  ```java
  Arrays.fill(r.getPassword(), '\0');
  ```
- Implement explicit cache eviction by zeroing sensitive fields before removing the map entry.
- Consider using OS-level secure memory (`mlock`) for especially sensitive credentials.


---

### Task 55 — Git Credentials Not Isolated or Validated for Private Repositories
- **Severity:** HIGH
- **Category:** Credential Management / Secret Handling
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 103–141
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 100–125
  - `app/src/main/java/io/xpipe/app/ext/ProcessControlProvider.java` — lines 78–80
- **CWE:** CWE-522 (Insufficiently Protected Credentials), CWE-213 (Exposure of Sensitive Information in Source Code)
- **Verification:** Confirmed - No credential parameter in cloneRepository interface.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
The `cloneRepository()` and `pullRepository()` methods accept only a URL and path. There is **no mechanism** to supply credentials for private Git repositories:

```java
public abstract void cloneRepository(String url, Path target) throws Exception;
```

Users who need to clone private repositories have limited options:
1. Embed credentials in the URL: `https://user:password@github.com/org/repo.git` (credentials in UI field, plaintext in config files, exposed in logs)
2. Use SSH keys with SSH agent (requires manual setup, not guided)
3. Use system Git credential store (shared with other applications, risky)

Additionally, if credentials are embedded in URLs and stored in configuration, they can be:
- Exposed in logs or error messages
- Leaked via memory dumps
- Captured by malware with process inspection capabilities

**Impact:**  
- Private repositories cannot be easily used without exposing credentials
- Credentials leak into config files, UI fields, and logs
- Shared system credential stores create cross-application risk

**Remediation:**
- Add a credential parameter to `cloneRepository()`:
  ```java
  public abstract void cloneRepository(String url, Path target, 
      SecretRetrievalStrategy credentials) throws Exception;
  ```
- Extract credentials from environment variables rather than URLs:
  ```bash
  GIT_USERNAME=user GIT_PASSWORD=token git clone https://github.com/...
  ```
- Support SSH-based URLs with SSH key authentication:
  ```
  ssh://git@github.com/org/repo.git
  ```
- Use `git credential` helper for secure credential storage.
- Never store plaintext passwords; use tokens/PATs with minimal scopes.
- Validate that credentials are not embedded in URLs; reject URLs containing `:` between `//` and `@`.


---

### Task 56 — Plaintext Entry Metadata Written to Disk Without Encryption
- **Severity:** HIGH
- **Category:** Data Encryption / Storage
- **Files:**
  - `app/src/main/java/io/xpipe/app/storage/DataStoreEntry.java` — lines 541–602
  - `app/src/main/java/io/xpipe/app/storage/DataStorageNode.java`
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 (Missing Encryption of Sensitive Data)
- **Verification:** Confirmed - entry.json written with plain JSON; only store.json encrypted.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Connection entries are persisted to disk as `entry.json` and `state.json` files. Key metadata fields are written **without encryption**, including:
- Connection name and category  
- UI state, expanded nodes, tree structure
- Metadata timestamps
- Entry UUID and parent references

```java
// DataStoreEntry.writeDataToDisk()
var entryString = mapper.writeValueAsString(obj);
var stateString = mapper.writeValueAsString(stateObj);
var storeString = mapper.writeValueAsString(DataStorageNode.encryptNodeIfNeeded(storeNode));

Files.writeString(directory.resolve("state.json"), stateString);
Files.writeString(directory.resolve("entry.json"), entryString);
Files.writeString(directory.resolve("store.json"), storeString);
```

**Impact:**  
An attacker with local filesystem access can enumerate all connection names, organizational structure, and entry UUIDs without needing to decrypt the vault data itself. Enables targeted attacks on infrastructure deployments.

**Remediation:**
- Encrypt field names and values using the vault's master key before serialization
- Store only UUIDs in plaintext; encrypt metadata
- Implement envelope encryption for entry metadata


---

### Task 57 — RDP and Remmina Config Files Created Without Owner-Only Permissions
- **Severity:** MEDIUM
- **Category:** File Access Control / Information Disclosure
- **Files:**
  - `app/src/main/java/io/xpipe/app/util/RemminaHelper.java` — lines 63–93
  - `app/src/main/java/io/xpipe/app/rdp/ExternalRdpClient.java` — lines 90–96
- **CWE:** CWE-276 (Incorrect Default Permissions), CWE-312 (Cleartext Storage of Sensitive Information)
- **Verification:** Confirmed - Files.writeString() without setting file permissions; credential files world-readable.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
RDP and Remmina config files are written with `Files.writeString()` without explicit permission enforcement:

```java
// RemminaHelper  (Remmina profile file — may contain password=<encrypted>)
Files.createDirectories(file.getParent());
Files.writeString(file, string);  // No permission set

// ExternalRdpClient  (.rdp file — may contain username, hostname, RDP options)
Files.writeString(file, string);  // No permission set
```

On POSIX systems the new file inherits the process umask, typically `0644` (world-readable). Both files contain at minimum usernames and hostnames, and the Remmina file may contain an encrypted password blob.

**Impact:**  
- Connection metadata (usernames, target hostnames, domain names) readable by any local user while the file exists.
- On systems with a permissive umask (`0022` or looser), the Remmina password blob is world-readable; combined with the shared 3DES key derivation (Task 91) this allows offline decryption.

**Remediation:**
- Set restrictive permissions immediately after creation:
  ```java
  if (OsType.ofLocal() != OsType.WINDOWS) {
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
  }
  ```
- On Windows, apply owner-only ACLs via `AclFileAttributeView`.
- Use `Files.createTempFile(parent, prefix, suffix, PosixFilePermissions.asFileAttribute(...))` to create atomically with correct permissions from the start.


### Task 58 — Verbose Request Tracing Risks Sensitive Data Exposure
- **Severity:** LOW
- **Category:** Information Disclosure
- **File:** `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — lines 89–96
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Verification:** Confirmed - Raw request JSON tree logged at trace level.
- **Non-default prerequisite:** Requires trace-level request logging to be enabled.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` *(worst-case assumes trace logging is enabled)*

**Description:**  
Raw parsed request trees and request objects are traced, and request payloads may include secrets/tokens depending on endpoint and data model.

```java
TrackEvent.trace("Parsed raw request:\n" + tree.toPrettyString());
TrackEvent.trace("Parsed request object:\n" + object);
```

**Impact:**  
Sensitive values can leak to logs/diagnostic sinks when trace logging is enabled.

**Remediation:**
- Redact secret-bearing fields before logging.
- Disable payload traces in production builds.


---

### Task 59 — SSH Key Passphrase Held as `java.lang.String` (Cannot Be Zeroed)
- **Severity:** MEDIUM
- **Category:** Memory Security / Credential Handling
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/InPlaceKeyStrategy.java` — lines 70–90
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/KeyFileStrategy.java` — lines 85–130
- **CWE:** CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **Verification:** Confirmed - Storage uses AES-encrypted InPlaceSecretValue, but UI layer (SecretFieldComp/PasswordField) decrypts via getSecretValue() returning immutable java.lang.String; ofString() creates bidirectional String bindings.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
SSH key passphrases flow through `SecretValue.getSecretValue()` which returns a `String`. Java `String`s are immutable and interned — their backing `char[]` cannot be zeroed by application code even after use:

**Note:** The concrete representation of the retrieved passphrase (e.g., `String` vs `char[]`) depends on the secret implementation. This audit does not include evidence of a safe, explicitly-zeroed buffer lifecycle for the SSH key passphrase in the visible code paths.

Additionally, passphrases passed as environment variables persist in the process environment map, which is accessible to any code within the JVM.

**Impact:**  
SSH key passphrases can be recovered from heap dumps, JVM diagnostic output (`jmap`), or process environment listings (`/proc/self/environ`) after the passphrase is no longer needed.

**Remediation:**
- Change `SecretValue.getSecretValue()` to return `char[]` rather than `String`.
- Zero the `char[]` immediately after the `ssh-add` command completes.
- Pass passphrases via a secure pipe/stdin mechanism rather than environment variables.
- Remove the `SSH_ASKPASS_PASSPHRASE` environment variable from the process environment after use.


---

### Task 60 — Predictable Temporary Filenames for Credential Files
- **Severity:** LOW
- **Category:** Race Condition / Credential Exposure
- **File:** `app/src/main/java/io/xpipe/app/pwman/KeeperPasswordManager.java` — lines 109, 477
- **CWE:** CWE-377 (Insecure Temporary File)
- **Verification:** Confirmed - Random().nextInt() for temp filenames; predictable.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
`java.util.Random` (not `SecureRandom`) generates temporary file names that hold 2FA codes and credentials:

```java
var file = sc.getSystemTemporaryDirectory()
    .join("keeper" + Math.abs(new Random().nextInt()) + ".txt");
```

The predictable filenames enable symlink attacks or race conditions on shared systems.

**Remediation:**
- Use `Files.createTempFile()` which uses a secure random generator and atomic file creation.
- Alternatively, replace `new Random().nextInt()` with `new SecureRandom().nextInt()`.
- Ensure the temp file is deleted immediately after use (ideally in a `finally` block).


---

### Task 61 — Bridge Config and Key Files Not Cleared After Vault Reset
- **Severity:** MEDIUM
- **Category:** Security Hygiene / Data Lifecycle
- **Files:**
  - `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — bridge directory management
  - Vault reset logic (vault clear/reset action)
- **CWE:** CWE-459 (Incomplete Cleanup), CWE-226 (Sensitive Information Uncleared Before Release)
- **Verification:** Confirmed - reset() kills shell but does not delete bridge keys, config, or PID file.
- **CVSS v4.0:** 6.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`

**Description:**  
When the user performs a vault reset or data directory clear, the SSH bridge key files and configuration are not specifically targeted for secure deletion. The bridge directory (`~/.xpipe/data/bridge/`) may contain:
- `xpipe_bridge` (Ed25519 private key)
- `xpipe_bridge.pub` (public key)
- `authorized_keys`
- `sshd_config`

Standard file deletion (`Files.delete()`) on many file systems merely unlinks the inode — the key data remains on disk until overwritten, and can be recovered with forensic tools.

**Impact:**  
After a user's "secure wipe" of XPipe data, SSH bridge private keys may be forensically recoverable from disk sectors, enabling post-wipe compromise of any previously reachable systems.

**Remediation:**
- Before deleting bridge key files, overwrite them with random bytes (or zeros):
  ```java
  var random = new SecureRandom();
  var overwrite = new byte[(int) Files.size(privateKeyPath)];
  random.nextBytes(overwrite);
  Files.write(privateKeyPath, overwrite);
  Files.delete(privateKeyPath);
  ```
- Or use platform-specific secure deletion utilities (`shred`, `sdelete`).
- Document that SSD/NVMe wear-leveling may prevent guaranteed secure deletion and recommend full-disk encryption as the primary defence.


---

### Task 62 — Authorization Header Parsing Is Non-Strict (Scheme Not Enforced)
- **Severity:** LOW
- **Category:** Authentication Hardening
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — line 55
  - `app/src/main/java/io/xpipe/app/beacon/mcp/AppMcpServer.java` — line 157
- **CWE:** CWE-287 (Improper Authentication)
- **Verification:** Confirmed - replace("Bearer ", "") not strict auth header parsing.
- **CVSS v4.0:** 6.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Token extraction strips the string `"Bearer "` via replacement instead of validating header format:

```java
var token = auth.replace("Bearer ", "");
...
var correct = apiKey.replace("Bearer ", "").equals(AppPrefs.get().apiKey().get());
```

This accepts non-standard Authorization formats (including raw token values without the Bearer scheme), weakening protocol expectations and making auth behavior ambiguous across clients/proxies.

**Impact:**  
While not an immediate bypass by itself, permissive parsing reduces defense-in-depth and increases risk of auth confusion bugs in integrations and middleware handling.

**Remediation:**
- Enforce strict `Authorization: Bearer <token>` parsing.
- Reject missing/invalid schemes with a clear 401/403 response.
- Normalize whitespace and parse once in a shared auth utility.


---

### Task 63 — Flexmark Library is Archived and Unmaintained
- **Severity:** LOW
- **Category:** Dependency Lifecycle
- **File:** `app/build.gradle` — lines 30–50
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **Verification:** Confirmed - Flexmark 0.64.8 (last release 2022); stale dependency.
- **CVSS v4.0:** 6.3 (Medium) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
`com.vladsch.flexmark` 0.64.8 (20+ modules) is used extensively in the project. Public ecosystem reports indicate the upstream repository may be archived/unmaintained; this should be verified directly before prioritizing migration work. If maintenance is indeed paused, future parser vulnerabilities (ReDoS, XSS in HTML output) may not receive upstream fixes.

**Remediation:**
- Plan migration to `commonmark-java` or another actively maintained Markdown library.
- In the interim, audit Flexmark usage to ensure no untrusted Markdown is rendered to HTML without sanitization.


---

### Task 64 — No Gradle Dependency Verification (Supply Chain Risk)
- **Severity:** LOW
- **Category:** Supply Chain
- **Files:** `build.gradle`, `settings.gradle`, `gradle/wrapper/gradle-wrapper.properties`
- **Evidence:** No Gradle dependency verification metadata file is present under `gradle/` in this repository.
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - No verification-metadata.xml present.
- **CVSS v4.0:** 6.3 (Medium) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The project does not include Gradle dependency verification metadata in the repository. Gradle supports dependency verification via SHA-256 checksums and PGP signatures to protect against dependency confusion and compromised artifacts.

**Remediation:**
```bash
./gradlew --write-verification-metadata sha256
```
Commit the generated verification metadata file and maintain it when dependencies change.


---

### Task 65 — Blob Storage Has No Quota/TTL and Can Grow Unbounded
- **Severity:** LOW
- **Category:** Availability / Storage Exhaustion
- **File:** `app/src/main/java/io/xpipe/app/beacon/BlobManager.java` — lines 20–23, 57–66
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - ConcurrentHashMap-backed memoryBlobs and fileBlobs maps have no TTL, no quota, no eviction, and no removal after consumption; reset() only runs on shutdown.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 6.0 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` *(worst-case assumes the HTTP API is enabled and blob endpoints are used)*

**Description:**  
Blob data is stored in memory/disk maps without eviction, quota, TTL, or explicit delete lifecycle per blob.

**Impact:**  
Repeated API usage can fill heap/disk and degrade service availability.

**Remediation:**
- Add per-blob TTL and periodic cleanup.
- Enforce global and per-client memory/disk quotas.
- Remove blob mappings after read/consumption when feasible.


---

### Task 66 — `FsWriteExchangeImpl` Uses `available()` for Blob Size (Truncation/Corruption Risk)
- **Severity:** LOW
- **Category:** Logic Bug / Data Integrity
- **File:** `app/src/main/java/io/xpipe/app/beacon/impl/FsWriteExchangeImpl.java` — line 19
- **CWE:** CWE-197 (Numeric Truncation Error), CWE-440 (Expected Behavior Violation)
- **Verification:** Confirmed - in.available() used as size metadata; unreliable for streams.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 6.0 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` *(worst-case assumes the HTTP API is enabled)*

**Description:**  
The `/fs/write` path derives `totalBytes` from `InputStream.available()` when opening the remote output stream:

```java
try (var in = BlobManager.get().getBlob(msg.getBlob());
        var os = fs.openOutput(msg.getPath(), in.available())) {
    in.transferTo(os);
}
```

`available()` is not a reliable stream length indicator and is limited to `int` semantics.

**Impact:**  
Large blobs (especially >2 GB) or streams with non-length-preserving `available()` behavior can pass incorrect size metadata to downstream file-write commands, causing truncated writes, failed transfers, or inconsistent remote file state.

**Remediation:**
- Track and persist blob length in `BlobManager` metadata.
- Pass the actual `long` length into `openOutput(...)` instead of `available()`.


---

### Task 67 — Unvalidated Native Message Length Enables Memory DoS / Crash
- **Severity:** MEDIUM
- **Category:** Availability / Input Validation
- **File:** `app/src/main/java/io/xpipe/app/pwman/KeePassXcProxyClient.java` — lines 397–401
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - No bounds check on message length field from proxy.
- **CVSS v4.0:** 5.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

**Description:**  
The native-message parser trusts a 32-bit length value from process stdout and allocates a byte array directly from it without bounds checks:

```java
int messageLength = lengthBuffer.getInt();
byte[] messageBytes = new byte[messageLength];
```

No validation exists for negative values or large lengths.

**Impact:**  
A malicious or compromised proxy process can force `NegativeArraySizeException` or excessive allocation (`OutOfMemoryError`), crashing the password-manager integration path and potentially destabilizing the app.

**Remediation:**
- Enforce strict bounds (e.g., `0 <= messageLength <= MAX_NATIVE_MESSAGE_BYTES`).
- Reject invalid lengths before allocation and terminate the session safely.


---

### Task 68 — Vault Directory Created With World-Readable Permissions
- **Severity:** MEDIUM
- **Category:** File Security / Permissions
- **Files:**
  - `app/src/main/java/io/xpipe/app/storage/StandardStorage.java` — lines 97–100
- **CWE:** CWE-276 (Incorrect Default Permissions), CWE-311 (Missing Encryption of Sensitive Data)
- **Verification:** Confirmed - StandardStorage uses FileUtils.forceMkdir() to create storage directories without explicit permission restriction (umask-dependent on POSIX).
- **CVSS v4.0:** 5.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The storage directories are created using `FileUtils.forceMkdir()`, which creates directories with default permissions (umask-dependent on POSIX). This can allow other local users to:
- List directory contents and enumerate connections
- Access entry.json and category.json files
- Potentially discover connection metadata before the vault is encrypted

```java
// app/src/main/java/io/xpipe/app/storage/StandardStorage.java
            FileUtils.forceMkdir(storesDir.toFile());
            FileUtils.forceMkdir(categoriesDir.toFile());
            FileUtils.forceMkdir(dataDir.toFile());
            FileUtils.forceMkdir(iconsDir.toFile());
```

**Impact:**  
Local privilege escalation vector; unprivileged users can enumerate sensitive connection metadata.

**Remediation:**
- Create vault directory with restrictive permissions (0700 on Unix)
- Use `Files.createDirectory()` with explicit `PosixFilePermissions.fromString("rwx------")`
- On Windows, ensure ACL denies access to EVERYONE and Users groups
- Document that multi-user systems should separate vault directories


---

### Task 69 — Beacon Auth File Path Fallback on Windows Can Resolve to Directory
- **Severity:** MEDIUM
- **Category:** Logic Bug / Availability
- **Files:**
  - `beacon/src/main/java/io/xpipe/beacon/BeaconConfig.java` — lines 61–67
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — lines 124–132
- **CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions)
- **Verification:** Confirmed - Directory-vs-file fallback bug in auth file logic.
- **CVSS v4.0:** 5.9 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

**Description:**  
When `%TMP%` resolves under `C:\Windows`, the fallback path is reassigned to `%LOCALAPPDATA%\TEMP` without appending `beacon-auth` filename:

```java
if (path.startsWith(Path.of("C:\\Windows"))) {
    path = Path.of(System.getenv("LOCALAPPDATA")).resolve("TEMP");
}
```

`initAuthSecret()` then writes directly to this path:

```java
Files.writeString(file, id);
```

If `file` is a directory, write fails and beacon startup degrades.

**Impact:**  
In affected Windows runtime contexts (service/system-like temp roots), local API auth file initialization can fail, causing beacon startup failure and loss of local API functionality.

**Remediation:**
- Always construct a full file path ending with `beacon-auth` after fallback.
- Ensure parent directory creation before writing.


---

### Task 70 — RDP `full address` Field Written to Config Files Without Validation
- **Severity:** MEDIUM
- **Category:** Command Injection / Hostname Validation
- **Files:**
  - `app/src/main/java/io/xpipe/app/util/RemminaHelper.java` — line 72
  - `app/src/main/java/io/xpipe/app/rdp/ExternalRdpClient.java` — lines 90–96
- **CWE:** CWE-20 (Improper Input Validation), CWE-78 (OS Command Injection)
- **Verification:** Confirmed - RdpConfig.toString() writes all property values directly to .rdp and .remmina config files without newline or special-character sanitization, enabling injection of additional RDP settings.
- **CVSS v4.0:** 5.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The `full address` value from `RdpConfig` is propagated directly into Remmina `.remmina` files and standard `.rdp` files without format validation:

```java
// RemminaHelper.java — value written directly
server=%s  // %s = config.get("full address").getValue()

// ExternalRdpClient.writeRdpConfigFile — whole RdpConfig.toString() written
var string = input.toString() + "\n";
Files.writeString(file, string);
```

If an attacker can influence the `full address` field (e.g., via an imported `.rdp` file, API-driven `connection/add`, or cloned store), they can inject:
- Newlines that add extra directives to the config file.
- Shell metacharacters that break downstream client invocation if any client re-evaluates the file through a shell.
- Specially crafted hostnames triggering parsing bugs in RDP clients.

**Impact:**  
- Config-file injection: a `full address` value containing `\n` can write arbitrary `.remmina`/`.rdp` key-value pairs.
- Potential RDP client-specific command execution on malformed hostnames.

**Remediation:**
- Validate `full address` against a strict `hostname[:port]` pattern before use: DNS label regex or numeric IP, port in `[1, 65535]`.
- Strip or reject newlines and shell metacharacters in all config values before writing to disk.
- Prefer `Files.writeString` with explicitly composed and validated lines rather than `toString()` on the entire config map.


---

### Task 71 — `ShellView.transferLocalFile` Uses `available()` (Large File Size Bug)
- **Severity:** MEDIUM
- **Category:** Logic Bug / Integer Boundary
- **File:** `app/src/main/java/io/xpipe/app/process/ShellView.java` — lines 183–185
- **CWE:** CWE-197 (Numeric Truncation Error)
- **Verification:** Confirmed - in.available() instead of Files.size() for file transfer sizing.
- **CVSS v4.0:** 5.7 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Local file transfer uses `InputStream.available()` as file size:

```java
try (var in = Files.newInputStream(localPath)) {
    writeStreamFile(target, in, in.available());
}
```

This produces an `int`-bounded estimate rather than a guaranteed `long` file length.

**Impact:**  
For large files, the write path receives incorrect byte counts, potentially breaking remote copy operations or producing partial/inconsistent uploads.

**Remediation:**
- Use `Files.size(localPath)` for authoritative length.
- Keep stream-based transfer unchanged, but pass true `long` size.


---

### Task 72 — Beacon API Returns Raw Throwable Objects to Clients
- **Severity:** MEDIUM
- **Category:** Information Disclosure / Error Handling
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — lines 116, 138, 167
  - `beacon/src/main/java/io/xpipe/beacon/BeaconServerErrorResponse.java` — lines 13–22
- **CWE:** CWE-209 (Information Exposure Through an Error Message)
- **Verification:** Confirmed - Raw Throwable in error response leaks internals.
- **CVSS v4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Server-side exceptions are serialized into API responses as full `Throwable` objects:

```java
writeError(exchange, new BeaconServerErrorResponse(cause, link), 500);
...
@Value
public class BeaconServerErrorResponse {
    Throwable error;
    String documentationLink;
}
```

Serializing exception objects can expose implementation details such as internal class names, stack traces, file paths, and nested cause chains to API clients.

**Impact:**  
Attackers can use detailed error responses to map internals and speed up exploit development (endpoint behavior discovery, file/path enumeration, framework fingerprinting). In mixed-trust local environments, this increases lateral attack efficiency.

**Remediation:**
- Replace raw `Throwable` in wire responses with a minimal stable error schema (`code`, `message`, `correlationId`).
- Keep full stack traces server-side only (logs/telemetry).
- Add endpoint-level redaction policy for known sensitive exception messages.


---

### Task 73 — MCP “Read-Only” Tool Set Includes Terminal Launching Actions
- **Severity:** LOW
- **Category:** Privilege Boundary / Safety Classification
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/mcp/AppMcpServer.java` — lines 59–68
  - `app/src/main/java/io/xpipe/app/beacon/mcp/McpTools.java` — lines 406–459
- **CWE:** CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control)
- **Verification:** Confirmed - open_terminal present in readOnlyTools list.
- **Non-default prerequisite:** Requires MCP tool access to be enabled/authorized for a client.
- **CVSS v4.0:** 5.3 (Medium) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` *(worst-case assumes MCP is enabled and a client is authorized)*

**Description:**  
`AppMcpServer` registers several tools as “read-only”, including `open_terminal` and `open_terminal_inline`:

```java
readOnlyTools.add(McpTools.openTerminal());
readOnlyTools.add(McpTools.openTerminalInline());
```

However, `open_terminal` triggers a concrete side effect: it starts/attaches to a shell session and launches a terminal window via `TerminalLaunch.launch()`:

```java
TerminalLaunch.builder()
    .entry(shellStore.get())
    .directory(FilePath.of(directory.orElse(null)))
    .command(shellSession.getControl())
    .launch();
```

These tools are therefore available even when “mutation tools” are disabled, undermining the intended safety boundary between read-only and potentially destructive actions.

**Impact:**  
An MCP client granted access only to “read-only” tools can still trigger user-visible actions (opening terminal windows and starting sessions). This can be abused for annoyance/DoS (spawning many terminals), social engineering (prompting users to run commands), or to surprise users who believe “read-only” means “no side effects”.

**Remediation:**
- Move `open_terminal` / `open_terminal_inline` behind the mutation tool toggle, or introduce a third tool class such as “interactive” requiring explicit enablement.
- Ensure the tool listing and UX communicate that opening terminals is a side effect.


---

### Task 74 — Local Bridge sshd Has No Rate Limiting for Failed Connections
- **Severity:** LOW
- **Category:** Brute-Force / Denial of Service
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Verification:** Confirmed - No MaxStartups or MaxAuthTries in sshd_config template.
- **CVSS v4.0:** 5.1 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**

The generated `sshd_config` for the local bridge does not set `MaxStartups` or `MaxAuthTries` to values that would throttle or disconnect clients that repeatedly fail authentication.

**Why It Matters:**

An attacker with access to the loopback interface can perform unlimited rapid authentication attempts against the bridge, potentially enabling brute-force of the bridge's host keys or disrupting bridge availability through connection exhaustion.

**Recommended Fix:**

Add `MaxStartups 3:50:10` and `MaxAuthTries 3` to the generated bridge `sshd_config` to limit concurrent incomplete authentication sessions and retries per connection.


---

### Task 75 — No Vault Access Audit Logging for Encryption Key Operations
- **Severity:** MEDIUM
- **Category:** Audit Logging / Accountability
- **Files:**
  - `app/src/main/java/io/xpipe/app/secret/EncryptionKey.java` — key derivation and usage
  - `app/src/main/java/io/xpipe/app/storage/DataStorageNode.java` — encryption/decryption calls
- **CWE:** CWE-778 (Insufficient Logging)
- **Verification:** Confirmed - Zero logging statements in key derivation methods.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
No audit trail exists for vault encryption key operations:
- When vault is unlocked
- Which entries are decrypted
- Vault key derivation timestamp
- Credential access patterns

This makes it impossible to detect unauthorized vault access or detect key misuse.

**Impact:**  
Compliance violations (HIPAA, PCI-DSS, SOC 2 require audit logging for cryptographic operations). Impossible to investigate security incidents involving credential access.

**Remediation:**
- Log all vault key derivation events with timestamp and originating process
- Log all decryption operations with entry UUID and count
- Store audit logs separately from vault data
- Implement centralized logging architecture for cryptographic operations


---

### Task 76 — Entry State Persisted Unencrypted During Runtime
- **Severity:** MEDIUM
- **Category:** Data Encryption / Memory
- **Files:**
  - `app/src/main/java/io/xpipe/app/storage/DataStoreEntry.java` — lines 400–450 (state property)
  - `app/src/main/java/io/xpipe/app/storage/DataStorageNode.java`
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Verification:** Confirmed - state.json written with persistentState as unencrypted JSON.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Entry state (UI preferences, connection config snapshots) is cached in memory and persisted to `state.json` unencrypted after every state change. This includes:
- Last used timestamp
- Expanded tree-view state
- UI shortcuts and bookmarks

**Impact:**  
Memory dumps or core files contain plaintext entry state and usage patterns. Filesystem cache may retain unencrypted copies of state updates.

**Remediation:**
- Encrypt state.json before writing
- Store UUID + encrypted state blob structure
- Clear sensitive state from memory after serialization
- Use `SecureRandom` for any ephemeral state identifiers


### Task 77 — Category Metadata Stored Unencrypted in directory.json
- **Severity:** MEDIUM
- **Category:** Data Encryption / Storage
- **Files:**
  - `app/src/main/java/io/xpipe/app/storage/DataStoreCategory.java` — lines 75–86, 188–213
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Verification:** Confirmed - `category.json` and `state.json` are written as plaintext JSON.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Category structure data is written to `category.json` and `state.json` without encryption:
- Category names (organizational names, team identifiers)
- Parent category UUIDs (hierarchy structure)
- Creation timestamps

```java
// app/src/main/java/io/xpipe/app/storage/DataStoreCategory.java
        var entryString = mapper.writeValueAsString(obj);
        var stateString = mapper.writeValueAsString(stateObj);
        FileUtils.forceMkdir(directory.toFile());
        Files.writeString(directory.resolve("category.json"), entryString);
        Files.writeString(directory.resolve("state.json"), stateString);
```

**Impact:**  
Reveals organizational structure and categorization strategy without requiring vault key. Can expose security-sensitive groupings (e.g., "critical-prod", "security-keys", "admin-accounts").

**Remediation:**
- Encrypt category names and metadata using vault master key
- Store only immutable identifiers in plaintext
- Implement category metadata encryption at persistence layer


---

### Task 78 — Transient Bridge Host Key Written to Predictable, Non-Validated Path
- **Severity:** LOW
- **Category:** Key Management / Path Security
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Verification:** Confirmed - Predictable host key path, no symlink check before generation.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**

The bridge generates an ephemeral host key and writes it to a static sub-path inside the application data directory. The path is constructed without verifying that no pre-existing file or symlink exists at that location, leaving a narrow window for a symlink-substitution attack before the key is written.

**Why It Matters:**

A local adversary who can pre-create a symlink at the target path can redirect key-write operations to an arbitrary file, potentially overwriting sensitive data or harvesting the private key material.

**Recommended Fix:**

Create the key with `StandardOpenOption.CREATE_NEW` (or the equivalent atomic exclusive-create call) so the write fails if the path already exists. Additionally verify the resolved canonical path is within the expected directory before writing.


### Task 79 — No Audit Logging for Git Repository Operations
- **Severity:** LOW
- **Category:** Logging / Compliance
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 135–141
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 109–116
- **CWE:** CWE-778 (Insufficient Logging)
- **Verification:** Confirmed - clone/pull operations are invoked directly in these code paths with no obvious audit logging wrapper in these methods.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Git clone/pull operations are executed without logging or audit trails:

```java
// ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java
            if (Files.exists(getLocalPath())) {
                ProcessControlProvider.get().pullRepository(getLocalPath());
            } else {
                ProcessControlProvider.get().cloneRepository(url, getLocalPath());
            }
```

```java
// app/src/main/java/io/xpipe/app/icon/SystemIconSource.java
            var dir = SystemIconManager.getPoolPath().resolve(id);
            if (!Files.exists(dir)) {
                ProcessControlProvider.get().cloneRepository(remote, dir);
            } else {
                ProcessControlProvider.get().pullRepository(dir);
            }
```

There is no record of:
- Which repositories were cloned
- When clones happened
- Which commit/tag was checked out
- Whether operations succeeded or failed
- Who initiated the operation (user context)

**Impact:**  
Difficult to audit or troubleshoot Git-related issues. Security incidents involving Git repositories cannot be properly investigated.

**Remediation:**
- Log Git operation metadata: operation (clone/pull), URL, target path, success/failure, commit hash, timestamp.
- Store audit logs in a tamper-evident format (append-only).
- Include Git operation metadata in central logging.


---

### Task 80 — No Encryption of Cached Credentials In Memory
- **Severity:** LOW
- **Category:** Memory Security / Credential Handling
- **Files:**
  - `app/src/main/java/io/xpipe/app/secret/SecretManager.java` — in-memory `Map<SecretReference, SecretValue>` cache
  - `app/src/main/java/io/xpipe/app/secret/SecretQueryProgress.java` — caches retrieved secrets via `SecretManager.cache(...)`
- **CWE:** CWE-311 (Missing Encryption of Sensitive Data), CWE-522 (Insufficiently Protected Credentials)
- **Verification:** Confirmed - Credentials cached as plain Java objects in HashMap.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Credentials loaded from the vault for active connections are cached in plaintext in memory. During credential rotation or connection update, old plaintext copies may remain in memory or in garbage collection buffers.

**Impact:**  
Memory dumps, JVM heap snapshots, and core files contain plaintext credentials for all active connections, negating the security benefit of vault encryption-at-rest.

**Remediation:**
- Use encrypted credential containers (e.g., XORed with ephemeral keys) for cached credentials
- Implement credential reference counting and immediate wiping after use
- Use `char[]` instead of `String` for passwords to enable explicit zeroing
- Perform garbage collection immediately after sensitive data use


---

### Task 81 — SSH Config Bridge Entry Persists After XPipe Uninstall
- **Severity:** LOW
- **Category:** Post-Uninstall Cleanup / Data Residue
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — `updateConfig()` method
- **CWE:** CWE-459 (Incomplete Cleanup)
- **Verification:** Confirmed - SSH config entry persists with no uninstall cleanup.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
When XPipe writes a `Host xpipe_bridge` entry to `~/.ssh/config`, there is no corresponding cleanup mechanism triggered by XPipe uninstall or data-directory deletion. The orphaned entry points to a port that is no longer bound:

```
# ~/.ssh/config after XPipe uninstall:
Host xpipe_bridge
    HostName localhost
    User "alice"
    Port 21477
    IdentityFile "/home/alice/.xpipe/data/bridge/xpipe_bridge_client"
```

The orphaned identity file path also becomes dangling, and any tooling that reads `~/.ssh/config` (IDEs, other SSH utilities) will encounter errors about the missing key file.

**Impact:**  
Stale config entries confuse other tools and leak information about the user having previously used XPipe (hostname, username, port mapping).

**Remediation:**
- Expose a `cleanup()` method on the bridge that removes the `Host xpipe_bridge` entry from `~/.ssh/config`.
- Call it from the uninstaller, from the "Factory Reset" action, and on abnormal startup detection.


---

### Task 82 — Agent Forwarding Not Restricted in Bridge Configuration
- **Severity:** MEDIUM
- **Category:** Privilege Escalation / Lateral Movement
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`, forwarding strategy code
- **CWE:** CWE-269 (Improper Privilege Management)
- **Verification:** Confirmed - No AllowAgentForwarding no or AllowTcpForwarding no directives.
- **CVSS v4.0:** 4.8 (Medium) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N`

**Description:**

The bridge `sshd_config` does not set `AllowAgentForwarding no`, and connection strategies do not explicitly suppress `-A` (agent forwarding). If a client connects with agent forwarding enabled, the bridge will accept it and forward key-signing requests to the client's agent.

**Why It Matters:**

If the bridge host is compromised, any forwarded agent allows the attacker to impersonate the client's SSH keys against third-party hosts, enabling lateral movement across the user's entire managed infrastructure.

**Recommended Fix:**

Set `AllowAgentForwarding no` in the bridge `sshd_config` unless agent forwarding is an explicitly supported and documented feature. When constructing client SSH commands, do not pass `-A` unless the user has consciously opted in.


---

### Task 83 — Beacon Session/Shell Caches Use Unsynchronized `HashSet` Under Multi-Threaded Access
- **Severity:** MEDIUM
- **Category:** Concurrency / Race Condition
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — line 37
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconCache.java` — line 14
  - `app/src/main/java/io/xpipe/app/beacon/BeaconRequestHandler.java` — lines 55–59
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Verification:** Confirmed - Plain HashSet under multi-threaded access.
- **CVSS v4.0:** 2.3 (Low) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Authentication sessions and shell sessions are stored in plain `HashSet` collections and accessed from a thread pool without consistent synchronization.

**Impact:**  
Potential race conditions, visibility issues, and rare runtime failures during concurrent add/remove/iterate operations.

**Remediation:**
- Replace with concurrent collections or synchronize access consistently.
- Introduce explicit session manager abstractions with thread-safe APIs.


---

### Task 84 — Large-File `/fs/read` Path Handling Bug Causes Incorrect File Readback
- **Severity:** LOW
- **Category:** Logic Bug / Availability
- **File:** `app/src/main/java/io/xpipe/app/beacon/impl/FsReadExchangeImpl.java` — lines 31–43
- **CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions)
- **Verification:** Confirmed - Path mismatch: writes to child path but reads parent.
- **Non-default prerequisite:** Requires the HTTP API to be enabled via `enableHttpApi` (default is disabled).
- **CVSS v4.0:** 2.3 (Low) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N` *(worst-case assumes the HTTP API is enabled)*

**Description:**  
In the large-file branch, data is written to `file.resolve(msg.getPath().getFileName())` but response reads from `file`.

```java
var file = BlobManager.get().newBlobFile();
try (var fileOut = Files.newOutputStream(file.resolve(msg.getPath().getFileName()))) {
    fixedIn.transferTo(fileOut);
}
...
try (var fileIn = Files.newInputStream(file); ... ) {
    fileIn.transferTo(out);
}
```

**Impact:**  
Large reads may fail or return incorrect output, creating reliability and potential data-loss behavior in automation.

**Remediation:**
- Write and read from the same exact path.
- Add regression tests for files above and below the size threshold.


---

### Task 85 — LXD/Incus Container CSV Parsing Is Fragile and Can Break Discovery
- **Severity:** MEDIUM
- **Category:** Logic Bug / Robustness / Availability
- **Files:**
  - `ext/system/src/main/java/io/xpipe/ext/system/lxd/LxdCommandView.java` — lines 151–154
  - `ext/system/src/main/java/io/xpipe/ext/system/incus/IncusCommandView.java` — lines 136–139
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - CSV split without bounds check.
- **CVSS v4.0:** 2.3 (Low) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Container listing parses CLI CSV output with direct positional indexing and no schema/length checks:

```java
return output.lines()
    .collect(Collectors.toMap(
        s -> s.strip().split(",")[0],
        s -> s.strip().split(",")[1],
        (x, y) -> y,
        LinkedHashMap::new));
```

Unexpected output rows (format changes, warnings in stdout, malformed lines) can trigger `ArrayIndexOutOfBoundsException` or map-construction failures.

**Impact:**  
A single malformed CLI line can break container discovery for LXD/Incus integrations, causing operational availability issues and failed automation.

**Remediation:**
- Parse with validated CSV/token count checks before indexing.
- Ignore/record malformed lines instead of failing whole collection.


---

### Task 86 — Unverifiable Local JAR Files (Supply Chain Risk)
- **Severity:** LOW
- **Category:** Supply Chain
- **File:** `app/build.gradle` — lines 91, 94
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Verification:** Confirmed - Local flat JAR dependencies; unsigned, unverifiable.
- **CVSS v4.0:** 2.3 (Low) — `CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Two dependencies are loaded as flat-dir local JARs with no integrity verification:
- `atlantafx-base-2.0.2.jar`
- `fx-builders-1.0.0-SNAPSHOT.jar`

These are opaque binaries in `gradle/gradle_scripts/`. Anyone with repository write access could replace them with malicious versions. The `SNAPSHOT` suffix indicates an unstable/unreleased artifact.

**Remediation:**
- Publish these to Maven Central (or a private authenticated repository) and consume as normal versioned dependencies.
- At minimum, add SHA-256 checksums alongside the JARs and verify them in the build script.


---

### Task 87 — `generatePublicSshKey()` Delegated to Unauditable Abstract Provider
- **Severity:** MEDIUM
- **Category:** Auditability / Supply Chain
- **File:** `app/src/main/java/io/xpipe/app/ext/ProcessControlProvider.java` — abstract method
- **CWE:** CWE-494 (Download of Code Without Integrity Check), CWE-1104 (Use of Unmaintained Third Party Components)
- **Verification:** Not auditable from this source tree - fully abstract method; implementation via `ServiceLoader` is not in this tree.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Public SSH key generation for identity strategies is delegated to a platform-specific abstract method:

```java
public abstract String generatePublicSshKey(SecretValue privateKey, SecretRetrievalStrategy passphrase);
```

The actual implementation is loaded at runtime via `ServiceLoader` from a closed-source or extension module not present in this source tree. Without being able to inspect the implementation, it is not possible to verify:
- Whether the correct key type and size are used
- Whether temporary key material is securely erased
- Whether the implementation writes any temporary key material to disk (and if so, with secure permissions and cleanup)
- Whether errors during generation are correctly reported

**Impact:**  
Security properties of SSH key generation (algorithm selection, parameter validation, memory cleanup) cannot be audited from the visible source. A compromised or insecure extension implementation could generate weak or predictable keys without detection.

**Remediation:**
- Document the expected contract for `generatePublicSshKey()` (algorithm, key size, error handling).
- Add integration tests that verify properties of generated keys (type, size, absence of weak parameters).
- Consider inlining key generation using `ssh-keygen` directly with explicit, auditable parameters rather than delegating to an opaque provider.


---

### Task 88 — Unbounded Startup Open-Argument Buffer Enables Local Memory DoS
- **Severity:** LOW
- **Category:** Availability / Resource Exhaustion
- **Files:**
  - `app/src/main/java/io/xpipe/app/core/AppOpenArguments.java` — lines 22, 35–38
  - `app/src/main/java/io/xpipe/app/core/AppDesktopIntegration.java` — lines 65–67
  - `app/src/main/java/io/xpipe/app/beacon/impl/DaemonOpenExchangeImpl.java` — lines 36–40
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - Unbounded bufferedArguments ArrayList; DoS vector.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
During startup, incoming open arguments are appended to a static in-memory list with no cap:

```java
private static final List<String> bufferedArguments = new ArrayList<>();
...
if (AppOperationMode.isInStartup()) {
    bufferedArguments.addAll(arguments);
    return;
}
```

Multiple entry points can feed this list while startup is in progress (desktop URI handler and daemon open exchange), and there is no size or count limit.

**Impact:**  
A local attacker (or any process repeatedly invoking the protocol handler) can induce excessive memory growth and delay/interrupt startup via argument flooding.

**Remediation:**
- Enforce strict caps on buffered argument count and cumulative byte size.
- Drop/trim oversized entries and emit a bounded warning event.
- Prefer a bounded queue with backpressure semantics over an unbounded `ArrayList`.


---

### Task 89 — No Connection Timeout (`ConnectTimeout`) or Keepalive Configuration
- **Severity:** LOW
- **Category:** Availability / Resource Exhaustion
- **Files:** `dist/changelog/1.7.16.md`, SSH connection providers (implementation-dependent)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Partially confirmed - `ConnectTimeout` is explicitly discussed and intentionally not specified per `dist/changelog/1.7.16.md`; no keepalive defaults are visible from this tree.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**

SSH connections established by XPipe do not visibly specify keepalive configuration (e.g., `ServerAliveInterval`, `ServerAliveCountMax`) in this source tree, and the project changelog explicitly discusses the decision to not specify `ConnectTimeout`.

**Why It Matters:**

A network partition or an unreachable host causes threads to block until the OS TCP timeout (often 2+ minutes). In scenarios with many managed nodes this can exhaust the thread pool and make the UI unresponsive.

**Recommended Fix:**

Inject `-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3` into all SSH invocations, or set equivalent library-level timeouts, and surface connection failure promptly in the UI.


---

### Task 90 — No Cryptographic Algorithm Pinning in Bridge `sshd_config`
- **Severity:** LOW
- **Category:** Cryptographic Agility / Downgrade Attack
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Verification:** Confirmed - No cipher/MAC/KexAlgorithm pinning in sshd_config.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**

The generated `sshd_config` does not restrict `Ciphers`, `MACs`, or `KexAlgorithms` to modern, NIST-approved or widely vetted selections. The system SSH binary's compiled-in defaults may include legacy algorithms (e.g., `arcfour`, `hmac-md5`, `diffie-hellman-group1-sha1`) that are known-weak.

**Why It Matters:**

A local attacker who can intercept or proxy the loopback connection (e.g., through a transparent proxy or packet capture) and force a downgrade to a legacy cipher can potentially decrypt session traffic.

**Recommended Fix:**

Pin the permitted cipher suites (example values):
- `Ciphers`: `aes256-gcm@openssh.com,chacha20-poly1305@openssh.com`
- `MACs`: `hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`
- `KexAlgorithms`: `curve25519-sha256,ecdh-sha2-nistp521`


---

### Task 91 — 3DES Cipher Usage in Remmina Integration
- **Severity:** MEDIUM
- **Category:** Cryptography
- **File:** `app/src/main/java/io/xpipe/app/util/RemminaHelper.java` — line 44
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Verification:** Confirmed - DESede/CBC/PKCS5Padding for Remmina interop.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
Triple-DES (`DESede/CBC/NoPadding`) is used to decrypt Remmina-encrypted passwords. 3DES has a 64-bit block size, making it vulnerable to the Sweet32 birthday attack, and is deprecated by NIST.

**Impact:**  
Limited — this is for interoperability with Remmina's existing encryption format. The risk is constrained to the Remmina import path.

**Remediation:**
- Document this as a known legacy limitation.
- If Remmina updates their format, migrate accordingly.
- Ensure the 3DES decryption path is only reachable when importing Remmina configurations.


---

### Task 92 — Unvalidated Executable Path in KeePassXC Proxy Client
- **Severity:** LOW
- **Category:** Input Validation
- **File:** `app/src/main/java/io/xpipe/app/pwman/KeePassXcProxyClient.java` — line 78
- **CWE:** CWE-426 (Untrusted Search Path)
- **Verification:** Confirmed - ProcessBuilder with List avoids shell injection, but executable path is not validated against a known-good location. Reclassified from command injection to executable path trust.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The `proxyExecutable` path is passed directly to `ProcessBuilder` without validation:

```java
var pb = new ProcessBuilder(List.of(proxyExecutable.toString()));
this.process = pb.start();
```

**Impact:**  
If the `proxyExecutable` path is user-controlled and not validated, it could lead to arbitrary command execution.

**Remediation:**
- Validate the `proxyExecutable` path to ensure it points to a legitimate KeePassXC executable.


---

### Task 93 — Local Bridge Binds on a Predictable, Non-Randomised Port
- **Severity:** LOW
- **Category:** Local Network Exposure
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Verification:** Confirmed - port = server.getPort() + 10; fixed offset, no collision detection.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**

The local SSH bridge selects a fixed or narrowly bounded port number rather than using an OS-assigned ephemeral port. This makes it trivial for other local processes to predict the port and attempt connections before legitimate clients.

**Why It Matters:**

A local malicious process that connects to the bridge port before the legitimate client may be able to enumerate available commands or probe bridge behaviour, widening the local attack surface.

**Recommended Fix:**

Bind to port `0` to receive an OS-assigned ephemeral port, then communicate that port to clients through a local IPC mechanism (e.g., a lock file containing the port number) rather than using a hardcoded value.


---

### Task 94 — SSH Key Path Not Validated Against Symlink Traversal Before Load
- **Severity:** LOW
- **Category:** Path Security / Key Integrity
- **Files:** `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/KeyFileStrategy.java`, `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/InPlaceKeyStrategy.java`
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Verification:** Confirmed - No symlink validation on key file paths.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**

When an SSH identity file path is resolved for loading, the code does not call `toRealPath()` or equivalent to resolve symlinks and verify the canonical path lies within an expected directory. An attacker who can create a symlink in a watched directory can redirect the key-load operation to an arbitrary file.

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/KeyFileStrategy.java
    private FilePath resolveFilePath(ShellControl sc) {
        var s = file.toAbsoluteFilePath(sc);
        // The ~ is supported on all platforms, so manually replace it here for Windows
        if (s.startsWith("~")) {
            s = s.resolveTildeHome(FilePath.of(AppSystemInfo.ofCurrent().getUserHome()));
        }
        return s;
    }
```

**Why It Matters:**

If key material is loaded from an attacker-controlled symlink target, the attacker can observe what data XPipe treats as a valid key or cause authentication to succeed with a key the attacker has planted.

**Recommended Fix:**

Resolve all identity file paths with `path.toRealPath(LinkOption.NOFOLLOW_LINKS)` (to detect symlinks) and verify the real path is within the user's designated key storage directory before loading.


---

### Task 95 — Git Clone Path Traversal via Malicious Repository Names
- **Severity:** LOW
- **Category:** Path Traversal / File System Security
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 118–127
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 42–52
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Verification:** Confirmed - Unsanitized URL-derived name used in Path.resolve().
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The local clone path is derived from the Git repository URL's filename without proper validation:

```java
// ScriptCollectionSource.java:118–127
private String getName() {
    var name = FilePath.of(url).getFileName();
    if (!name.isEmpty()) {
        return name;  // No validation — could be "../../../path"
    }
    return UuidHelper.generateFromObject(url).toString();
}

@Override
public Path getLocalPath() {
    return AppCache.getBasePath().resolve("scripts").resolve(getName());
}
```

A malicious URL like `https://server.com/../../../etc/passwd.git` would resolve to accessing the system's `/etc` directory.

**Impact:**  
A user could be tricked into cloning a repository with a malicious URL that escapes intended directories and overwrites system files or configuration.

**Remediation:**
- Validate the repository name/directory doesn't contain path traversal sequences:
  ```java
  var name = FilePath.of(url).getFileName();
  if (name.contains("..") || name.contains("/") || name.contains("\\")) {
      throw new ValidationException("Invalid repository name: " + name);
  }
  ```
- Use a hash of the URL for the directory name instead of the parsed filename:
  ```java
  var hash = MessageDigest.getInstance("SHA-256").digest(url.getBytes());
  return AppCache.getBasePath().resolve("scripts").resolve(toHexString(hash));
  ```
- Canonicalize paths and ensure they're within the expected base directory:
  ```java
  var resolved = AppCache.getBasePath().resolve("scripts").resolve(name).toRealPath();
  if (!resolved.startsWith(AppCache.getBasePath().resolve("scripts"))) {
      throw new SecurityException("Path traversal detected");
  }
  ```


### Task 96 — Bridge sshd Process Not Monitored for Unexpected Exit
- **Severity:** MEDIUM
- **Category:** Process Management / Availability
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd process handle
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **Verification:** Confirmed - No thread/callback monitors for unexpected sshd exit.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L`

**Description:**  
After launching the bridge sshd, XPipe does not retain a reference to the sshd process handle or monitor it for unexpected exit:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
            var control =
                    ProcessControlProvider.get().createLocalProcessControl(true).start();
            control.writeLine(launchCommand.buildFull(control));
            INSTANCE.setRunningShell(control);
```

If sshd crashes or is killed by a system OOM killer or security tool after successful startup, subsequent SSH connection attempts fail with connection-refused errors, and there is no alert or automatic restart.

**Impact:**  
Silent bridge failures. Users experience inexplicable SSH session drops without any diagnostic. Automation relying on the bridge cannot self-heal.

**Remediation:**
- Submit a background task that detects unexpected exit and surfaces a diagnostic to the user.
- Optionally implement automatic restart with exponential backoff.


---

### Task 97 — Git Remote Origin Can Be Modified If Local Repository Is Writable
- **Severity:** LOW
- **Category:** Repository Integrity
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 115, 138
  - `app/src/main/java/io/xpipe/app/icon/SystemIconSource.java` — lines 112, 114
- **CWE:** CWE-276 (Incorrect Default Permissions)
- **Verification:** Confirmed - pullRepository() called without remote origin validation.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
After cloning a Git repository, the local clone is stored in the XPipe data directory with standard user permissions. If the directory has group-writable or world-writable permissions, an attacker (or malware running as another user) can modify the `.git/config` file to change the remote origin:

For example: `git config remote.origin.url https://attacker-server.com/repo.git`

The relevant code paths perform `pullRepository(...)` based on directory existence and do not validate the configured remote origin against an expected URL before pulling.

On the next `pull`, the application pulls from the attacker's repository instead of the original.

**Impact:**  
An attacker with local write access can poison cloned repositories by changing their remote origins.

**Remediation:**
- Ensure cloned repository directories are owner-only (chmod 0700 on POSIX, appropriate ACLs on Windows).
- Validate the remote origin before pulling:
  ```java
  var actualOrigin = getRemoteOrigin(path);
  if (!actualOrigin.equals(expectedUrl)) {
      throw new SecurityException("Remote origin mismatch: expected " + expectedUrl + " but found " + actualOrigin);
  }
  ```
- Make `.git/config` immutable after initial clone.


---

### Task 98 — Orphan SSH Agent Processes Not Reaped After Bridge Crash
- **Severity:** LOW
- **Category:** Resource Management / Process Lifecycle
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java`
  - `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — shutdown path
- **CWE:** CWE-401 (Missing Release of Memory After Effective Lifetime), CWE-459 (Incomplete Cleanup)
- **Verification:** Confirmed - reset() kills shell only if explicitly invoked; no JVM shutdown hook for bridge sshd.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
On Windows, XPipe can start the OpenSSH agent service, but does not track or reap it on abnormal termination:

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java
sc.executeSimpleBooleanCommand("ssh-agent start");
```

Orphaned `ssh-agent` processes retain loaded key material. An attacker discovering the agent's `SSH_AUTH_SOCK` path can connect to it and use the loaded keys without needing the passphrase.

**Impact:**  
Post-crash key material persists in orphaned agent processes. On multi-session workstations, stale agents accumulate and increase the exploitation window for loaded SSH keys.

**Remediation:**
- Register a JVM shutdown hook to kill spawned agent processes:
  ```java
  Runtime.getRuntime().addShutdownHook(new Thread(() -> agentProcess.destroy()));
  ```
- Record spawned agent PIDs and clean them up on startup if XPipe did not shut down cleanly.
- Set `SSH_AGENT_LIFETIME` where supported to automatically expire loaded keys.


---

### Task 99 — MCP Help Text Misrepresents “Read-Only” Tools as Safe
- **Severity:** LOW
- **Category:** Security UX / Misleading Safety Guarantees
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/mcp/McpTools.java` — lines 55–58
- **CWE:** CWE-451 (User Interface (UI) Misrepresentation of Critical Information)
- **Verification:** Confirmed - Misleading safe to use help text for read-only tool set.
- **Non-default prerequisite:** Requires MCP to be enabled and a user to enable/allow MCP tool access.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N`

**Description:**  
The MCP `help` tool states that read-only tools “will not modify anything on your system and are safe to use”:

```java
These tools will not modify anything on your system and are safe to use.
```

This assurance is too strong:
- Some “read-only” tools have side effects (Task 73).
- Other “read-only” tools can still expose sensitive data (e.g., `read_file`, `list_files`, and `find_file` can reveal secrets and credentials stored on connected systems).

**Impact:**  
Users may enable MCP read-only tools under the impression they are “safe”, increasing the chance of credential/data exfiltration via prompt injection or a compromised MCP client, and causing surprise side effects (terminal launching).

**Remediation:**
- Reword `help` to describe read-only tools as “non-modifying” rather than “safe”, explicitly warning about data exposure.
- Prefer explicit enablement prompts for data-exfiltration-capable tools.


---

### Task 100 — `sshd_config` Does Not Restrict `PreferredAuthentications`
- **Severity:** LOW
- **Category:** SSH Server Hardening
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd_config template
- **CWE:** CWE-287 (Improper Authentication)
- **Verification:** Confirmed - Server-side sshd_config sets PasswordAuthentication=no but lacks AuthenticationMethods=publickey and KbdInteractiveAuthentication=no; client config in ~/.ssh/config lacks PreferredAuthentications=publickey.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The bridge sshd_config disables `PasswordAuthentication` but does not set `PreferredAuthentications` to restrict the authentication method list to `publickey` only. Other methods (keyboard-interactive, GSSAPI, host-based) may still be attempted by connecting clients, increasing the attack surface of the bridge authentication exchange:

```
PasswordAuthentication no
# Missing: PreferredAuthentications publickey
# Missing: AuthenticationMethods publickey
```

**Impact:**  
Low practical risk on modern OpenSSH, but explicit restriction is a defence-in-depth measure that prevents authentication method confusion bugs or regressions from future sshd versions.

**Remediation:**
- Add to template:
  ```
  PreferredAuthentications publickey
  AuthenticationMethods publickey
  ```


---

### Task 101 — `sshd_config` Missing `MaxAuthTries` Limit
- **Severity:** MEDIUM
- **Category:** SSH Server Hardening / Brute-Force Protection
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd_config template
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Verification:** Confirmed - No MaxAuthTries in sshd_config template.
- **CVSS v4.0:** 2.1 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The generated `sshd_config` does not set `MaxAuthTries`. OpenSSH's default is 6, but without an explicit directive a future configuration change at the OpenSSH package level could silently increase it. On a locally-accessible sshd, omitting explicit limits allows more authentication attempts per connection than necessary:

The bridge `sshd_config` template is generated as:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
            var content = """
                          ForceCommand %s
                          PidFile "%s"
                          StrictModes no
                          SyslogFacility USER
                          LogLevel Debug3
                          Port %s
                          PasswordAuthentication no
                          HostKey "%s"
                          PubkeyAuthentication yes
                          AuthorizedKeysFile "%s"
                          """.formatted(
                            command,
                            pidFile.toString(),
                            "" + port,
                            INSTANCE.getHostKey().toString(),
                            INSTANCE.getPubIdentityKey());
```

**Impact:**  
An attacker with local access can attempt more key pairs per connection than a hardened configuration would permit, increasing the viability of key-material brute-force attacks.

**Remediation:**
- Add `MaxAuthTries 2` to the sshd_config template (key-based auth should succeed in 1 attempt).
- Add `LoginGraceTime 10` to limit the authentication window per connection.


---

### Task 102 — No Recovery Mechanism for Incomplete or Corrupted Git Clones
- **Severity:** LOW
- **Category:** Availability / Data Integrity
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/script/ScriptCollectionSource.java` — lines 135–141
- **CWE:** CWE-440 (Expected Behavior Violation)
- **Verification:** Confirmed - Files.exists() check then pull; corrupt clone passes with no recovery fallback.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
If a Git clone operation fails or is interrupted halfway through (e.g., network interruption), the partial clone remains on disk:

```java
if (Files.exists(getLocalPath())) {
    ProcessControlProvider.get().pullRepository(getLocalPath());  // Assumes valid clone
} else {
    ProcessControlProvider.get().cloneRepository(url, getLocalPath());
}
```

On the next attempt, the code assumes the directory contains a valid `.git` repository and attempts to pull. If the clone was corrupted, the pull will fail or use inconsistent state.

**Impact:**  
- Corrupted repository state persists indefinitely.
- Users cannot recover without manually deleting the directory.
- Confusing error messages if partially-cloned repo is in a bad state.

**Remediation:**
- Validate that the repository is in a consistent state before attempting operations:
  ```java
  if (Files.exists(getLocalPath())) {
      var isValidGit = isValidGitRepository(getLocalPath());
      if (isValidGit) {
          ProcessControlProvider.get().pullRepository(getLocalPath());
      } else {
          // Remove corrupted clone and retry
          FileUtils.deleteDirectory(getLocalPath());
          ProcessControlProvider.get().cloneRepository(url, getLocalPath());
      }
  }
  ```
- Implement retry logic with exponential backoff.
- Log and report corrupted repository state to the user.


---

### Task 103 — Bridge Port Collision Not Detected Before Binding
- **Severity:** MEDIUM
- **Category:** Availability / Resource Management
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — lines 52–53
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-772 (Missing Release of Resource after Effective Lifetime)
- **Verification:** Confirmed - No ServerSocket availability check before sshd launch.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The bridge port is derived as `server.getPort() + 10` and used directly in the `sshd_config` without first checking whether the port is already in use:

```java
var port = server.getPort() + 10;
// No: ServerSocket.bind() probe, ss -tnlp check, or /proc/net/tcp scan
// sshd will fail to bind if port is taken; failure is surfaced as opaque error
```

If another process occupies the port (or if the previous bridge sshd did not release it cleanly), the new bridge sshd silently fails to bind during startup.

**Impact:**  
On port contention, the bridge silently fails to start, and subsequent SSH connection attempts receive unexplained authentication errors. No diagnostic is surfaced to explain the failure.

**Remediation:**
- Before launching sshd, probe the port with a `ServerSocket` to verify availability:
  ```java
  try (var probe = new ServerSocket(port)) { /* port is free */ }
  catch (BindException e) { throw new BridgeStartException("Port " + port + " already in use"); }
  ```
- On collision, either increment the port or emit a clear diagnostic.


### Task 104 — `IdentityFile none` Literal Used as Fallback Instead of Disabling Fallthrough
- **Severity:** LOW
- **Category:** Configuration Correctness
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/NoIdentityStrategy.java`
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/CustomAgentStrategy.java`
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/OpenSshAgentStrategy.java`
- **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)
- **Verification:** Confirmed - Literal none as IdentityFile value.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N`

**Description:**

In some code paths, when no identity file is selected, the SSH invocation appends `-i none` or `IdentityFile none` as a placeholder to suppress default key loading. The literal path `none` does not exist and will generate warnings; more importantly, the intent (preventing default key loading) is not reliably achieved across all OpenSSH versions.

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/NoIdentityStrategy.java
        return List.of(
                new KeyValue("IdentitiesOnly", "yes"),
                new KeyValue("IdentityAgent", "none"),
                new KeyValue("IdentityFile", "none"),
                new KeyValue("PKCS11Provider", "none"));
```

**Why It Matters:**

On some platforms, the literal `none` fallback is ignored and OpenSSH proceeds to try default identity files (`~/.ssh/id_rsa`, etc.), potentially authenticating with keys the user did not intend to use for this connection.

**Recommended Fix:**

Use `-o IdentityAgent=none -o IdentitiesOnly=yes` together to reliably disable both agent-sourced and file-sourced default identities when no explicit identity is configured.


---

### Task 105 — SSH Identity Entries Accumulate in `~/.ssh/config` Without Expiry
- **Severity:** LOW
- **Category:** Configuration Integrity / Information Disclosure
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`, identity strategy helpers
- **CWE:** CWE-459 (Incomplete Cleanup)
- **Verification:** Confirmed - SshLocalBridge.updateConfig() writes to ~/.ssh/config with fragile regex replacement and no cleanup on uninstall/reset; stale entries persist if format drifts.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**

Each new connection profile that specifies an SSH identity appends an `IdentityFile` directive to the user's global `~/.ssh/config`, but there is no mechanism to remove stale entries when a connection profile is deleted or the identity path changes.

**Why It Matters:**

Over time the config file grows with paths to no-longer-valid or relocated key files. If those paths are later reused by unrelated software, they may be implicitly loaded for unintended SSH connections.

**Recommended Fix:**

Maintain identity configuration in a per-xpipe include file (`~/.ssh/config.d/xpipe`) and regenerate it entirely on each start, removing entries for deleted profiles.


---

### Task 106 — Bridge SSH Config Not Isolated from User's Global `~/.ssh/config`
- **Severity:** LOW
- **Category:** Configuration Isolation
- **Files:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java`
- **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)
- **Verification:** Confirmed - Direct write to ~/.ssh/config.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:L/SA:N`

**Description:**

XPipe writes bridge settings directly into the user's global `~/.ssh/config`. Changes made by XPipe are interleaved with the user's own configuration, making it difficult to audit or remove XPipe-specific settings and creating the risk that XPipe's `Host xpipe-*` blocks accidentally override or are overridden by user stanzas.

**Why It Matters:**

A user who manually edits `~/.ssh/config` may inadvertently corrupt XPipe's bridge stanza; conversely, XPipe updates may silently change the user's effective SSH behaviour for non-XPipe hosts.

**Recommended Fix:**

Write bridge configuration exclusively to `~/.ssh/config.d/xpipe` (or similar) and add a single `Include ~/.ssh/config.d/xpipe` line to the user's config only once. Manage that include file entirely within XPipe's control.


---

### Task 107 — Beacon Port Parsing Lacks Validation and Can Break Startup
- **Severity:** LOW
- **Category:** Configuration Validation / Availability
- **Files:**
  - `beacon/src/main/java/io/xpipe/beacon/BeaconConfig.java` — lines 23–31
  - `app/src/main/java/io/xpipe/app/core/mode/AppOperationMode.java` — lines 123–133
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - Integer.parseInt without range validation on port.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
`BeaconConfig.getUsedPort()` parses environment/system values directly with `Integer.parseInt(...)` and does not validate allowed TCP port range.

Invalid values (non-numeric, negative, >65535) propagate into startup path selection and can trigger startup exceptions.

**Impact:**  
Malformed environment/config values can disable beacon setup during initialization, causing availability regressions for local API consumers.

**Remediation:**
- Validate parsed values are in `[1, 65535]`.
- On invalid input, log warning and fall back to default port.


---

### Task 108 — MD5 Used for Integrity Checking (Icon Cache)
- **Severity:** MEDIUM
- **Category:** Cryptography
- **File:** `app/src/main/java/io/xpipe/app/icon/SystemIconCache.java` — line 175
- **CWE:** CWE-328 (Use of Weak Hash)
- **Verification:** Confirmed - MD5 used for cache digesting.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
MD5 is used for icon cache integrity verification:

```java
var md = MessageDigest.getInstance("MD5");
```

MD5 is cryptographically broken — collisions can be computed in seconds.

**Impact:**  
Low practical risk in this context (cache validation only), but a cache poisoning attack via crafted collision is theoretically possible.

**Remediation:**
- Replace with SHA-256: `MessageDigest.getInstance("SHA-256")`.


---

### Task 109 — `ssh-keygen` Exit Code Not Verified After Host Key Generation
- **Severity:** MEDIUM
- **Category:** Error Handling / Cryptographic Integrity
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — lines 57–85
- **CWE:** CWE-252 (Unchecked Return Value)
- **Verification:** Confirmed - Both ssh-keygen calls use .execute() instead of .executeAndCheck().
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`

**Description:**  
When generating the bridge host key, the `ssh-keygen` command is executed but its exit code is not verified:

```java
sc.command(CommandBuilder.of()
    .add("ssh-keygen", "-q", "-C").addQuoted("XPipe SSH bridge host key")
    .add("-t", "ed25519", "-N", "\"\"")
    .add("-f").addQuoted(hostKey.toString()))
    .execute();  // .execute() — no return-value check, no .executeAndCheck()
// If ssh-keygen fails (missing binary, permission denied, disk full), hostKey file
// is not created; subsequent sshd start fails with an opaque "file not found" error
```

**Impact:**  
Silent key generation failures result in the bridge starting without a valid host key, causing confusing downstream authentication errors. On systems where `ssh-keygen` is absent (some minimal containers), the failure is invisible.

**Remediation:**
- Replace `.execute()` with `.executeAndCheck()` or check return value:
  ```java
  if (!sc.command(keygenCmd).executeAndCheck()) {
      throw new BridgeSetupException("ssh-keygen failed; check sshd binary availability and permissions");
  }
  ```


---

### Task 110 — RDP Config File Parser Lacks Type and Schema Validation
- **Severity:** MEDIUM
- **Category:** Input Validation / Logic Bug
- **File:** `app/src/main/java/io/xpipe/app/util/RdpConfig.java` — lines 43–62
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - parseContent() splits on : with no type/schema validation.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
`RdpConfig.parseContent()` splits each line on `:` with `limit=3` and accepts the result without any schema validation:

```java
content.lines().forEach(s -> {
    var split = s.split(":", 3);
    if (split.length < 2) {
        return;  // silently drops the line
    }
    if (split.length == 2) {
        map.put(split[0].strip(), new RdpConfig.TypedValue("s", split[1].strip()));
    }
    if (split.length == 3) {
        map.put(split[0].strip(), new RdpConfig.TypedValue(split[1].strip(), split[2].strip()));
    }
});
```

Issues:
- The type field (second token) is accepted as-is; no validation against the legal RDP type set `{ s, i, b }`.  
- Malformed or adversarially-crafted `.rdp` files silently skip or misparse records.  
- Values that legitimately contain `:` (UNC paths, IPv6 addresses, registry entries) are truncated at the second colon because the fragment after the third part is discarded.
- No key allow-list; arbitrary option names are accepted and passed downstream.

**Impact:**  
- Malformed imported `.rdp` files can produce silently incorrect connection parameters.
- Values containing `:` are truncated, potentially breaking addresses like `[::1]:3389`.
- No guard against injecting unexpected RDP directives that downstream RDP clients may execute.

**Remediation:**
- Validate the type token against the set `{ "s", "i", "b" }` and reject unknown types.
- Maintain an allow-list of known RDP key names; log and optionally reject unknown keys.
- Parse the value portion after the *second* `:` correctly as the full remainder (already handled by `limit=3`) but test and document this for IPv6 and UNC values.
- Add regression tests with adversarial input: IPv6 addresses, paths with multiple colons, empty values.


---

### Task 111 — Beacon Auth Secret File Is Written Without Symlink-Safe Atomic Create
- **Severity:** LOW
- **Category:** Local File Security Hardening
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — line 128
  - `beacon/src/main/java/io/xpipe/beacon/BeaconConfig.java` — lines 62–64
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **Verification:** Confirmed - Auth file written without symlink-safe atomic creation.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The beacon auth secret is written using a direct `Files.writeString(file, id)` to a temp-path-derived location:

```java
var file = BeaconConfig.getLocalBeaconAuthFile();
Files.writeString(file, id);
```

The write path does not explicitly enforce `CREATE_NEW` / `NOFOLLOW_LINKS` semantics, so link handling is left to default filesystem behavior.

**Impact:**  
In local tampering scenarios (same-user or misconfigured temp-directory ACLs), this can enable file clobber/link-following behavior and reduce robustness of auth secret handling.

**Remediation:**
- Create the file atomically with `CREATE_NEW` and fail if it already exists.
- Reject symbolic links using `NOFOLLOW_LINKS` checks before write.
- Apply owner-only permissions at creation time where supported.


---

### Task 112 — Non-Atomic Preference and Notes Persistence (Risk of Corruption and Symlink-Following Writes)
- **Severity:** LOW
- **Category:** Local File Write Hardening
- **Files:**
  - `app/src/main/java/io/xpipe/app/prefs/AppPrefsStorageHandler.java` — lines 49, 73–74
  - `app/src/main/java/io/xpipe/app/prefs/AppPrefs.java` — lines 447–448, 915–916
- **CWE:** CWE-367 (Time-of-check Time-of-use (TOCTOU) Race Condition)
- **Verification:** Confirmed - Non-atomic preference writes; corruption on crash.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Preferences are persisted by writing directly to JSON files (both the global `settings/preferences.json` and vault `preferences.json`) without an atomic write pattern:

```java
JacksonMapper.getDefault().writeValue(file.toFile(), content);
```

Additionally, the notes template is written directly to disk:

```java
Files.writeString(AppProperties.get().getDataDir().resolve("storage", "notes.md"), notesTemplate.getValue());
```

Direct writes can leave partially-written/corrupted files on crash or power loss, and default file write operations can follow symlinks in the target path if the directory becomes attacker-controlled.

**Impact:**  
Primarily reliability/data-integrity risk (corrupted preferences/notes). In adversarial local scenarios, symlink-following writes can contribute to file clobbering within the same user context.

**Remediation:**
- Use an atomic write pattern: write to a temporary file in the same directory, `fsync`, then `Files.move(..., ATOMIC_MOVE, REPLACE_EXISTING)`.
- On POSIX, set restrictive permissions on created files (e.g., `0600`) and ensure directories are owner-only where appropriate.
- Consider rejecting symlinks for security-sensitive persistence paths.


---

### Task 113 — Linux Shared Temp Parent Directory Uses `0777`
- **Severity:** MEDIUM
- **Category:** Local Security Hardening / Symlink Risk
- **File:** `app/src/main/java/io/xpipe/app/core/AppLocalTemp.java` — lines 19–23
- **CWE:** CWE-378 (Creation of Temporary File With Insecure Permissions)
- **Verification:** Confirmed - rwxrwxrwx on shared parent temp dir.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
On Linux, the shared XPipe temp parent is explicitly set to world-writable/executable (`rwxrwxrwx`).

**Impact:**  
In multi-user contexts, permissive temp roots increase risk of symlink/race abuse around derived temp artifacts.

**Remediation:**
- Use least-privilege permissions for shared temp roots.
- Prefer owner-only dirs for sensitive flows and use atomic secure temp APIs.


---

### Task 114 — Local SSH Bridge Starts `sshd` Without Explicit Localhost Bind and With `StrictModes no`
- **Severity:** LOW
- **Category:** Local Service Hardening
- **Files:**
  - `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — lines 108–120
- **CWE:** CWE-284 (Improper Access Control)
- **Verification:** Confirmed - StrictModes no, LogLevel Debug3, no ListenAddress restriction.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`

**Description:**  
The SSH terminal bridge dynamically generates an `sshd_config` that includes:

```text
StrictModes no
LogLevel Debug3
Port <derived>
AuthorizedKeysFile "<dataDir>/ssh_bridge/xpipe_bridge.pub"
```

The configuration does not set an explicit `ListenAddress 127.0.0.1` / `ListenAddress ::1`. Depending on the platform `sshd` defaults, the bridge may listen on all interfaces. Additionally, `StrictModes no` disables `sshd`’s permission sanity checks for keys/config paths.

**Impact:**  
This increases the attack surface of the local bridge service:
- Potential remote exposure if `sshd` binds beyond localhost (even if key-only auth limits access).
- Reduced robustness against local misconfiguration/tampering because `StrictModes` checks are disabled.

**Remediation:**
- Add `ListenAddress 127.0.0.1` (and `::1` where applicable) to force loopback-only binding.
- Set `StrictModes yes` and ensure bridge key/config files are created with owner-only permissions.
- Reduce `LogLevel` from `Debug3` to a less verbose value unless needed for troubleshooting.


---

### Task 115 — `BEACON_PORT` Environment Variable Is Ignored Unless System Property Is Also Set
- **Severity:** LOW
- **Category:** Logic Bug / Configuration Handling
- **Files:**
  - `app/src/main/java/io/xpipe/app/beacon/AppBeaconServer.java` — lines 57–63
  - `beacon/src/main/java/io/xpipe/beacon/BeaconConfig.java` — lines 23–31
- **CWE:** CWE-670 (Always-Incorrect Control Flow Implementation)
- **Verification:** Confirmed - BEACON_PORT env var silently ignored when property set.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
`setupPort()` only calls `BeaconConfig.getUsedPort()` when the Java system property is present:

```java
if (System.getProperty(BeaconConfig.BEACON_PORT_PROP) != null) {
    port = BeaconConfig.getUsedPort();
} else {
    port = BeaconConfig.getDefaultBeaconPort();
}
```

But `getUsedPort()` is the method that actually checks the `BEACON_PORT` environment variable.

**Impact:**  
Deployments setting only `BEACON_PORT` (without the system property) do not get the expected port, leading to confusing misconfiguration and local API connectivity failures.

**Remediation:**
- Always call `getUsedPort()` in `setupPort()` and separately track whether source was property/env/default.


---

### Task 116 — `WezTerminalType` Crashes on Linux When `XDG_RUNTIME_DIR` Is Unset
- **Severity:** LOW
- **Category:** Logic Bug / Environment Handling
- **File:** `app/src/main/java/io/xpipe/app/terminal/WezTerminalType.java` — lines 59–61
- **CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions)
- **Verification:** Confirmed - XDG_RUNTIME_DIR null causes NPE.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Linux socket directory resolution uses environment value directly in `Path.of(...)`:

```java
if (OsType.ofLocal() == OsType.LINUX) {
  return Path.of(System.getenv("XDG_RUNTIME_DIR"), "wezterm");
}
```

If `XDG_RUNTIME_DIR` is absent, `Path.of(null, ...)` throws at runtime.

**Impact:**  
On Linux environments without `XDG_RUNTIME_DIR` (minimal shells/containers/non-standard sessions), WezTerm detection/opening paths can fail with runtime exceptions, breaking terminal integration.

**Remediation:**
- Guard for null/blank `XDG_RUNTIME_DIR` and fall back to a safe user-scoped path.


---

### Task 117 — Fragile Port Parsing in `ServiceProtocolType.Custom` Breaks Non-IPv4 Inputs
- **Severity:** LOW
- **Category:** Logic Bug / Input Parsing
- **File:** `ext/base/src/main/java/io/xpipe/ext/base/service/ServiceProtocolType.java` — line 125
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - url.split(":")[1] fragile parsing, no bounds check.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Custom service opening extracts the port using `url.split(":")[1]`:

```java
var port = url.split(":")[1];
```

This is brittle for values containing additional `:` separators (e.g., IPv6 literals or scheme-prefixed values).

**Impact:**  
Can produce incorrect port extraction and broken launch commands for valid endpoint formats, leading to failed connections/automation.

**Remediation:**
- Parse with `URI`/`InetSocketAddress` semantics or split from the right-most `:` with validation.


---

### Task 118 — KeePassXC Association UI Can Crash on Short/Corrupt Key Material
- **Severity:** LOW
- **Category:** Logic Bug / Input Validation
- **File:** `app/src/main/java/io/xpipe/app/pwman/KeePassXcAssociationComp.java` — lines 27–28
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - substring(0,6) with no length guard.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The UI masks association keys by blindly slicing the first 6 characters:

```java
var key = associationKey.getKey().getSecretValue();
var censoredKey = key.substring(0, 6) + "*".repeat(key.length() - 6);
```

No length/null validation is performed before `substring(0, 6)`.

**Impact:**  
If persisted or synced association data is malformed/short, opening password-manager settings can throw `StringIndexOutOfBoundsException` and break the associated UI flow.

**Remediation:**
- Validate for null/length and use safe masking (`Math.min(6, key.length())`).
- Reject invalid association records on deserialization.


---

### Task 119 — Partial-Read Handling Bug in Native Messaging Protocol
- **Severity:** LOW
- **Category:** Logic Bug / Protocol Robustness
- **File:** `app/src/main/java/io/xpipe/app/pwman/KeePassXcProxyClient.java` — lines 390–404
- **CWE:** CWE-440 (Expected Behavior Violation)
- **Verification:** Confirmed - Single read() call with no loop; partial read risk.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The parser assumes `InputStream.read(...)` returns the full requested byte count in one call for both header and body. This is not guaranteed by the Java I/O contract.

**Impact:**  
Legitimate partial reads can trigger false protocol errors/timeouts, causing intermittent failures and brittle KeePassXC communication under load or buffered pipe fragmentation.

**Remediation:**
- Replace single `read(...)` calls with `readNBytes(...)` (JDK 11+) or a loop that accumulates until the required count is reached.


---

### Task 120 — `LocalFileTracker` Retains Deleted Entries Indefinitely
- **Severity:** LOW
- **Category:** Logic Bug / Resource Lifecycle
- **File:** `app/src/main/java/io/xpipe/app/util/LocalFileTracker.java` — lines 11–22
- **CWE:** CWE-401 (Missing Release of Memory After Effective Lifetime)
- **Verification:** Confirmed - reset() never clears the localFiles set; unbounded growth.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
`reset()` deletes tracked files but never clears the backing `localFiles` set.

**Impact:**  
Long-running sessions or repeated reset/init cycles can accumulate stale path references, causing unnecessary memory growth and repeated redundant delete attempts.

**Remediation:**
- Call `localFiles.clear()` after cleanup in `reset()`.


---

### Task 121 — sshd Launch Exit Code Not Verified Within Timeout
- **Severity:** MEDIUM
- **Category:** Process Management / Reliability
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — lines 120–140
- **CWE:** CWE-252 (Unchecked Return Value), CWE-755 (Improper Handling of Exceptional Conditions)
- **Verification:** Confirmed - sshd launched fire-and-forget; no exit-code check, no readiness verification.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
After launching the bridge sshd process, the code proceeds without verifying that the sshd process started and bound successfully. A brief sleep is used instead of deterministic readiness detection:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
            var control =
                    ProcessControlProvider.get().createLocalProcessControl(true).start();
            control.writeLine(launchCommand.buildFull(control));
            INSTANCE.setRunningShell(control);
```

Any configuration error in the generated `sshd_config` (malformed path, unavailable algorithm, permission denial) causes sshd to exit with code 1, which is never checked.

**Impact:**  
Silent bridge startup failures cause subsequent SSH connection attempts to fail with opaque errors. Operators cannot distinguish between a bridge that never started and one that started but is unreachable.

**Remediation:**
- Wait for a deterministic readiness signal (PID file creation, port binding, or process alive check) rather than a fixed sleep:
  ```java
  long deadline = System.currentTimeMillis() + 5000;
  while (!isBridgeListening(port) && System.currentTimeMillis() < deadline) Thread.sleep(100);
  if (!isBridgeListening(port)) throw new BridgeStartException("sshd failed to bind within 5 seconds");
  ```
- Check the sshd process exit code after the wait period.


---

### Task 122 — Race Condition in ServiceAddressRotation
- **Severity:** LOW
- **Category:** Race Condition
- **File:** `ext/base/src/main/java/io/xpipe/ext/base/service/ServiceAddressRotation.java` — lines 12-25
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Verification:** Confirmed - Unsynchronized HashMap + counter; race condition.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The `getRotatedLocalhost` method accesses and modifies a static `HashMap` (`replacedUrls`) and a static `counter` without synchronization:

```java
    static String getRotatedLocalhost(String url) {
        if (!url.startsWith("localhost")) {
            return url;
        }

        if (replacedUrls.containsKey(url)) {
            return replacedUrls.get(url);
        }

        var alias = aliases[counter++ % aliases.length];
        var replaced = url.replaceFirst("localhost", alias);
        replacedUrls.put(url, replaced);
        return replaced;
    }
```

**Impact:**  
Concurrent calls to this method can lead to `HashMap` corruption (e.g., infinite loops during resizing) or incorrect counter increments.

**Remediation:**
- Use a `ConcurrentHashMap` for `replacedUrls` and an `AtomicInteger` for `counter`, or synchronize the method.


---

### Task 123 — Race Condition in SystemIconManager
- **Severity:** LOW
- **Category:** Race Condition
- **File:** `app/src/main/java/io/xpipe/app/icon/SystemIconManager.java` — lines 20-21
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Verification:** Confirmed - Inconsistent synchronization on icon manager state.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The `SystemIconManager` uses static `HashSet` and `HashMap` collections (`loadedIconImages`, `LOADED_SOURCES`, `ICONS`) which are accessed and modified concurrently without consistent synchronization. While some methods like `getAndLoadIconFile` and `reloadSources` are synchronized, others like `getIcon` and `initAdditional` are not.

**Impact:**  
Concurrent access can lead to `ConcurrentModificationException` or inconsistent state.

**Remediation:**
- Use concurrent collections (e.g., `ConcurrentHashMap`, `CopyOnWriteArraySet`) or ensure all access to these collections is synchronized.


---

### Task 124 — Race Condition in TerminalMultiplexerManager
- **Severity:** LOW
- **Category:** Race Condition
- **File:** `app/src/main/java/io/xpipe/app/terminal/TerminalMultiplexerManager.java` — line 13
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Verification:** Confirmed - Unsynchronized static fields.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The `TerminalMultiplexerManager` uses a static `HashMap` (`connectionHubRequests`) which is accessed and modified concurrently without synchronization.

**Impact:**  
Concurrent access can lead to `HashMap` corruption or inconsistent state.

**Remediation:**
- Use a `ConcurrentHashMap` for `connectionHubRequests`.


---

### Task 125 — Race Condition in OsLogoComp
- **Severity:** LOW
- **Category:** Race Condition
- **File:** `app/src/main/java/io/xpipe/app/hub/comp/OsLogoComp.java` — line 22
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **Verification:** Confirmed - Unsynchronized lazy HashMap population.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The `OsLogoComp` uses a static `HashMap` (`ICONS`) which is populated lazily in `getImage` without synchronization.

**Impact:**  
Concurrent calls to `getImage` can lead to `HashMap` corruption or redundant file system operations.

**Remediation:**
- Use a `ConcurrentHashMap` for `ICONS` or synchronize the initialization block.


---

### Task 126 — `updateConfig()` Writes to `~/.ssh/config` Non-Atomically (TOCTOU)
- **Severity:** MEDIUM
- **Category:** Race Condition / File Integrity
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — lines 210–230
- **CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)
- **Verification:** Confirmed - Files.writeString() directly on ~/.ssh/config; no atomic write pattern.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`

**Description:**  
`updateConfig()` reads the existing `~/.ssh/config`, modifies it in memory, and writes it back in a non-atomic fashion:

```java
// app/src/main/java/io/xpipe/app/util/SshLocalBridge.java
        var file = AppSystemInfo.ofCurrent().getUserHome().resolve(".ssh", "config");
        if (!Files.exists(file)) {
            Files.writeString(file, hostEntry);
            return;
        }

        var content = Files.readString(file).lines().collect(Collectors.joining("\n")) + "\n";
        var pattern = Pattern.compile("""
                                      Host %s
                                       {4}HostName localhost
                                       {4}User "(.+)"
                                       {4}Port (\\d+)
                                       {4}IdentityFile "(.+)"
                                      """.formatted(getName()));
        var matcher = pattern.matcher(content);
        if (matcher.find()) {
            var replaced = matcher.replaceFirst(Matcher.quoteReplacement(hostEntry));
            Files.writeString(file, replaced);
            return;
        }

        // Probably an invalid entry that did not match
        if (content.contains("Host " + getName())) {
            return;
        }

        var updated = content + "\n" + hostEntry + "\n";
        Files.writeString(file, updated);
```

Between the read and write, another process (including another XPipe instance or the SSH client itself) can read or write the config, producing a corrupted or double-written result. On crash between read and write, the config file is left in its original state without the bridge entry, causing silent connection failures.

**Impact:**  
Concurrent SSH clients reading `~/.ssh/config` during the write window may get a partially-written or corrupted file. Double-writes from multiple XPipe instances produce duplicate `Host` entries. Power loss during write truncates the SSH config, potentially stranding all SSH connections.

**Remediation:**
- Use an atomic write pattern: write to `~/.ssh/config.xpipe-tmp`, then `Files.move()` with `ATOMIC_MOVE` and `REPLACE_EXISTING`.
- Acquire a `FileLock` on the config file before modifying.
- Check for duplicate entries before appending to prevent accumulation on repeated startups.


---

### Task 127 — Bridge PID File Not Deleted on Normal or Abnormal Shutdown
- **Severity:** LOW
- **Category:** Resource Cleanup / File Management
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — line 110
- **CWE:** CWE-459 (Incomplete Cleanup)
- **Verification:** Confirmed - reset() kills shell but PID file never deleted.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
A `sshd.pid` file is created in the bridge directory during sshd startup but is never explicitly deleted by XPipe on shutdown, crash, or bridge stop:

```java
var pidFile = bridgeDir.resolve("sshd.pid");
// pidFile path passed to sshd_config as PidFile directive
// Not deleted in stop(), not cleaned in startup pre-check
```

Stale PID files accumulate across restarts. If a PID in a stale file is recycled by the OS to a different process, monitoring/cleanup tools may incorrectly target the wrong process.

**Impact:**  
Stale PID files cause ambiguity during startup (is the bridge already running?). Automated monitoring tools may SIGTERM an unrelated process whose PID matched a stale bridge PID.

**Remediation:**
- Delete the PID file on bridge stop:
  ```java
  Files.deleteIfExists(pidFile);
  ```
- On startup, if the PID file exists, verify the referenced PID is a live sshd process before assuming the bridge is running; delete the file if the process is gone.


---

### Task 128 — `AppFontSizes.apply` Registers Global Listeners Without Lifecycle Cleanup
- **Severity:** LOW
- **Category:** Resource Lifecycle / Memory Leak
- **File:** `app/src/main/java/io/xpipe/app/core/AppFontSizes.java` — lines 66–81
- **CWE:** CWE-401 (Missing Release of Memory After Effective Lifetime)
- **Verification:** Confirmed - Font-size listeners never removed; memory leak.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
Each call to `AppFontSizes.apply(node, ...)` subscribes listeners to global preference observables and captures `node` in closures:

```java
// app/src/main/java/io/xpipe/app/core/AppFontSizes.java
        AppPrefs.get().theme().subscribe((newValue) -> {
            var effective = newValue != null ? newValue.getFontSizes().get() : getDefault();
            setFont(node, function.apply(effective));
        });

        AppPrefs.get().useSystemFont().addListener((ignored, ignored2, newValue) -> {
            var effective = AppPrefs.get().theme().getValue() != null
                    ? AppPrefs.get().theme().getValue().getFontSizes().get()
                    : getDefault();
            setFont(node, function.apply(effective));
        });
```

No deregistration occurs when the node is detached/disposed.

**Impact:**  
In long-lived sessions with dynamic view creation, stale node references can accumulate, increasing memory usage and causing unnecessary style updates on detached UI nodes.

**Remediation:**
- Bind/unbind listeners to node lifecycle (e.g., scene/window presence) and remove listeners on detach.
- Consider weak listeners where appropriate.


---

### Task 129 — Bridge Startup Does Not Clean Orphan Resources From Prior Crash
- **Severity:** MEDIUM
- **Category:** Resource Management / Reliability
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — startup initialization
- **CWE:** CWE-459 (Incomplete Cleanup), CWE-772 (Missing Release of Resource after Effective Lifetime)
- **Verification:** Confirmed - init() returns early if INSTANCE set; no cleanup of stale PID files or orphan processes.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
If XPipe terminates abnormally while the bridge is running, the following orphan artifacts may persist:
- The sshd process itself (still binding the port)
- The `sshd.pid` file (Task 127)
- The sshd_config file (pointing to stale paths)
- The `~/.ssh/config` bridge entry (still referencing the dead port)
- SSH agent processes (Task 98)

On the next startup, bridge initialization does not perform a cleanup pass for these artifacts. If the previous sshd is still alive and binding the port, a new bridge instance cannot start.

**Impact:**  
After an abnormal termination, the bridge fails to start on next launch due to undiscovered resource conflicts. Users must manually identify and kill orphan processes or clear stale config.

**Remediation:**
- During startup, before launching sshd:
  1. Check if the bridge directory's sshd.pid process is alive; if so, SIGTERM it.
  2. Verify the configured port is free (Task 103).
  3. Remove stale PID/config files.
  4. Update or re-write the `~/.ssh/config` entry.
- Register a JVM shutdown hook to perform cleanup synchronously at exit.


---

### Task 130 — `SSH_AUTH_SOCK` Set Without Validating Socket Existence
- **Severity:** LOW
- **Category:** SSH Configuration / Input Validation
- **Files:**
  - `ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java`
  - `app/src/main/java/io/xpipe/app/prefs/SshCategory.java`
- **CWE:** CWE-20 (Improper Input Validation)
- **Verification:** Confirmed - On POSIX, no socket-existence pre-check before setting SSH_AUTH_SOCK/IdentityAgent; relies on ssh-add failure for detection. Windows has explicit checkNamedPipeExists().
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The configured agent socket path is used in agent checks without a basic existence/type validation step (on POSIX the code relies on downstream `ssh-add` failure to detect problems):

```java
// ext/base/src/main/java/io/xpipe/ext/base/identity/ssh/SshIdentityStateManager.java
        try (var c = sc.command(CommandBuilder.of().add("ssh-add", "-l").fixedEnvironment("SSH_AUTH_SOCK", authSock))
                .start()) {
            var r = c.readStdoutAndStderr();
```

A user-supplied path that does not exist, is a regular file, or points to a directory will be silently accepted and will cause opaque failures downstream.

**Impact:**  
Invalid socket configurations degrade SSH authentication silently, leading to confusing error messages that do not identify the root cause.

**Remediation:**
- Validate the socket path on write (in the preferences UI) and on read:
  ```java
  if (!Files.exists(socketPath)) throw new ConfigException("SSH agent socket not found: " + socketPath);
  if (!socketPath.toFile().isPath()) throw new ConfigException("Not a socket: " + socketPath);
  ```
- Show a preference-level warning in the UI if the configured socket is not reachable.


---

### Task 131 — `sshd_config` Missing `ClientAliveInterval` for Idle Connection Reaping
- **Severity:** LOW
- **Category:** SSH Server Hardening / Resource Management
- **File:** `app/src/main/java/io/xpipe/app/util/SshLocalBridge.java` — sshd_config template
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Verification:** Confirmed - No ClientAliveInterval in sshd_config template.
- **CVSS v4.0:** 2.0 (Low) — `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`

**Description:**  
The sshd_config template does not configure `ClientAliveInterval` or `ClientAliveCountMax`. Idle or dead connections are never reaped by the bridge sshd:

(See the `sshd_config` template snippet in Task 101; it does not include `ClientAliveInterval` / `ClientAliveCountMax`.)

Network interruptions that do not close the TCP connection cleanly leave zombie sessions indefinitely. These zombie sessions consume file descriptors and may hold internal state in XPipe.

**Impact:**  
On networks with NAT or firewalls that silently drop idle connections, zombie sessions accumulate over time, consuming resources and potentially causing connection handshake failures once the sshd max-sessions limit is hit.

**Remediation:**
- Add to template:
  ```
  ClientAliveInterval 60
  ClientAliveCountMax 3
  ```


---

### Task 132 — Passphrase Prompt Dialog Has No Inactivity Timeout
- **Severity:** LOW
- **Category:** UI Security / Credential Exposure
- **Files:** `app/src/main/java/io/xpipe/app/util/AskpassAlert.java`, `app/src/main/java/io/xpipe/app/secret/SecretPromptStrategy.java`
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **Verification:** Confirmed - No inactivity timeout on passphrase dialog.
- **CVSS v4.0:** 1.0 (Low) — `CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N`

**Description:**

When XPipe prompts the user for an SSH key passphrase, the dialog remains open indefinitely without an inactivity timeout. If the user steps away from the machine while the dialog is displayed, any person with physical or remote access to the screen session can observe the passphrase as it is typed or see the prompt awaiting input.

**Why It Matters:**

An unattended passphrase prompt is a social-engineering opportunity: a bystander or RDP viewer can read keystrokes or submit a captured passphrase.

**Recommended Fix:**

Add a configurable auto-dismiss timeout (e.g., 60 seconds) to the passphrase dialog that cancels the authentication attempt and allows the user to retry, reducing the window during which the prompt is exposed.


---

### Task 133 — User Home Directory Lookup via eval echo ~user
- **Severity:** INFO
- **Category:** Command Injection (Theoretical)
- **File:** `app/src/main/java/io/xpipe/app/process/OsFileSystem.java` — line 126
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Verification:** Confirmed - eval echo ~user pattern; shell expansion risk.
- **CVSS v4.0:** N/A — Informational finding

**Description:**  
```java
var eval = pc.command("eval echo ~" + user).readStdoutIfPossible();
```

The `user` variable comes from the remote system's current username. If a username on a compromised remote system contains shell metacharacters, this could inject commands. Risk is very low in practice.

**Recommendation:** Use `getent passwd <user>` or `id -d` to look up home directories without `eval`.

---

### Task 134 — ObjectInputStream Deserialization in SentryErrorHandler
- **Severity:** INFO
- **Category:** Deserialization
- **File:** `app/src/main/java/io/xpipe/app/issue/SentryErrorHandler.java` — lines 72–75
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Verification:** Confirmed - ObjectInputStream.readObject() used for in-memory Throwable cloning; input is self-serialized (not attacker-controlled) but pattern is unsafe if exception chains contain gadget-eligible objects from classpath.
- **CVSS v4.0:** N/A — Informational finding

**Description:**  
Native Java deserialization (`ObjectInputStream.readObject()`) is used to clone a `Throwable` via serialize/deserialize round-trip. While the data source is internal (not from external input), this pattern is inherently dangerous if the exception contains attacker-controlled nested objects. Libraries like Jackson, Bouncy Castle, or Reactor on the classpath may provide gadget chains.

**Recommendation:** Replace with a direct clone method or use a safer deep-copy utility.

---

### Task 135 — Shell Dialect Quoting Implementations Not Auditable from This Source Tree
- **Severity:** INFO
- **Category:** Design
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Verification:** Not auditable from this source tree - `ServiceLoader` loads shell dialect implementations not present here.
- **CVSS v4.0:** N/A — Informational finding

**Description:**  
`ShellDialect.quoteArgument()`, `fileArgument()`, and `literalArgument()` are loaded via `ServiceLoader` from separate modules (not in this repo). Without inspecting those implementations, it is impossible to verify correct sanitization across all shell types (bash, cmd, powershell, fish, zsh, etc.). The default `getCdCommand()` uses only double-quote wrapping with no escaping.

**Recommendation:** Audit the shell dialect implementations in the private extension modules. Add comprehensive test cases for metacharacter handling in each dialect.

---

### Task 136 — CommandBuilder.add() is Unsafe by Default
- **Severity:** INFO
- **Category:** Design / Code Quality
- **File:** `app/src/main/java/io/xpipe/app/process/CommandBuilder.java`
- **CWE:** CWE-78 (OS Command Injection)
- **Verification:** Confirmed - add() stores raw Fixed tokens, bypasses quoting.
- **CVSS v4.0:** N/A — Informational finding

**Description:**  
`CommandBuilder.add(String)` inserts strings as-is without quoting. All uses with dynamic values (instead of `.addQuoted()`, `.addFile()`, or `.addLiteral()`) are potential injection points. A code audit or linting rule should flag all `.add()` calls with non-constant arguments.

**Recommendation:** Add a static analysis rule or code review checklist item to flag `CommandBuilder.add()` with dynamic arguments.

---

_End of audit._

---