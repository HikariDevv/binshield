<div align="center">

# binshield

**Offline static PE (`.exe` / `.dll`) security analyzer in pure Java.**

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-16a34a?style=flat-square)](https://github.com/HikariDevv/binshield)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

Inspects Windows PE32 / PE32+ binaries locally without uploading files to external servers.<br/>
Parses real PE headers and the Import Address Table (IAT), detects packers/overlays, maps findings to **MITRE ATT&CK**, and extracts embedded IOCs.

</div>

---

## Preview

```text
$ java -jar dist/binshield.jar sample.exe

  binshield — static PE analysis
  File      : sample.exe (312.40 KB)
  SHA-256   : 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  Entropy   : 7.41 / 8.00
  PE Type   : EXE · x64 (64-bit) · Native · Windows GUI · Unsigned
  Imports   : 2 DLLs (9 functions)

  SECTION    RAW_SIZE   VIRT_SIZE  FLAGS  ENTROPY
  UPX0       0          131072     RWX    0.00
  UPX1       284672     286720     RWX    7.92
  .rsrc      18432      18040      R--    4.18

  Findings (3):
  [CRITICAL] T1027     RWX PE Section             UPX1 has Read+Write+Execute (RWX) (+30)
  [HIGH    ] T1027.002 High Section Entropy       UPX1 entropy 7.92 (packed/encrypted) (+22)
  [HIGH    ] T1027.007 Dynamic API Stub           LoadLibrary + GetProcAddress with only 9 total imports (+22)

  Verdict   : HIGH RISK (74/100)  [11.2 ms]
```

---

## Analysis Engine

| Layer | What It Inspects | MITRE ATT&CK |
| :--- | :--- | :---: |
| **PE32 / PE32+ Parser** | DOS/COFF/Optional headers, architecture, EXE/DLL, `.NET` CLR header, Authenticode signature presence, entry-point anomalies, and PE overlays. | `T1027.009` |
| **Real IAT Parser** | Resolves Data Directory #1 via RVA-to-file-offset mapping to list every imported DLL and Windows API function. | `T1027.007` |
| **Packers & RWX** | Flags `RWX` sections, high per-section Shannon entropy (`>= 7.25`), and known packers (`UPX`, `VMProtect`, `Themida`, `ASPack`, `MPRESS`). | `T1027.002` |
| **Process Injection** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`, `SetThreadContext`. | `T1055` |
| **Keyloggers & Spyware** | `SetWindowsHookEx`, `GetAsyncKeyState`, `GetClipboardData`, `BitBlt`, `CreateCompatibleBitmap`. | `T1056` / `T1113` |
| **Stealers & Webhooks** | `CryptUnprotectData`, browser/Discord/crypto wallet paths, Discord webhooks, and Telegram bot endpoints. | `T1555` / `T1041` |
| **Defense Evasion** | `AmsiScanBuffer`, `EtwEventWrite`, Defender exclusion commands, `IsDebuggerPresent`, `VirtualProtect`. | `T1562` / `T1622` |
| **Persistence & Execution** | Registry `Run` keys, `schtasks /create`, Windows services, hidden PowerShell, `certutil`, `URLDownloadToFile`. | `T1547` / `T1059` |

---

## Quick Start

### Requirements
- **JDK 17** or newer.

### Build

**Windows**
```bat
mkdir out dist
javac --release 17 -d out src\com\dips\binshield\*.java
jar cfe dist\binshield.jar com.dips.binshield.Main -C out .
```

**Linux / macOS**
```bash
mkdir -p out dist
javac --release 17 -d out src/com/dips/binshield/*.java
jar cfe dist/binshield.jar com.dips.binshield.Main -C out .
```

---

## Usage

### Scan a file
```bash
java -jar dist/binshield.jar C:\path\to\file.exe
```

### Inspect the full Import Table (IAT) and all IOCs
```bash
java -jar dist/binshield.jar file.dll --imports --iocs
```

### Recursively scan a folder
```bash
java -jar dist/binshield.jar scan ./downloads
```

### JSON output
```bash
java -jar dist/binshield.jar scan file.exe --json
```

---

## Note

`binshield` performs **static heuristic analysis** and does not replace a full antivirus or dynamic sandbox. Legitimate packed installers or game anti-cheats may trigger high-entropy or anti-debug findings.

## License

Released under the [MIT License](LICENSE).
