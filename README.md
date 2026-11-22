<div align="center">

# binshield

**Offline static PE (`.exe` / `.dll`) security analyzer in pure Java.**

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-16a34a?style=flat-square)](https://github.com/HikariDevv/binshield)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

Inspects Windows executables and DLLs locally without uploading files to third-party servers.<br/>
Parses PE headers, computes per-section Shannon entropy, flags suspicious Windows APIs, and extracts embedded IOCs.

</div>

---

## Preview

```text
$ java -jar dist/binshield.jar sample.exe

  binshield — static PE analysis
  File     : sample.exe (312.40 KB)
  SHA-256  : 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  Entropy  : 7.41 / 8.00
  PE Type  : EXE · x64 (64-bit) · Windows GUI
  Compiled : 2026-10-14T19:22:10Z

  SECTION    RAW_SIZE   VIRT_SIZE  FLAGS  ENTROPY
  UPX0       0          131072     RWX    0.00
  UPX1       284672     286720     RWX    7.92
  .rsrc      18432      18040      R--    4.18

  Findings (3):
  [CRITICAL] PE Section                   RWX section detected: UPX1 (RWX) (+28)
  [HIGH    ] Packing / Encryption         High entropy in UPX1 (7.92) (+20)
  [CRITICAL] Process Injection            Matched: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread (+30)

  Verdict  : HIGH RISK (78/100)  [12.4 ms]
```

---

## What It Checks

| Category | Signals Analyzed |
| :--- | :--- |
| **PE Binary Structure** | DOS/COFF/Optional headers, architecture (`x86`/`x64`/`ARM64`), EXE vs DLL, subsystem, compile timestamp, and section table. |
| **Packers & RWX Sections** | Flags `RWX` (Read + Write + Execute) sections and known packer names (`UPX`, `VMProtect`, `Themida`, `ASPack`, `MPRESS`). |
| **Shannon Entropy** | Computes exact entropy (`0.00–8.00`) per section to spot encrypted or obfuscated payloads (`>= 7.25`). |
| **Process Injection** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`. |
| **Keyloggers & Stealers** | `SetWindowsHookEx`, `GetAsyncKeyState`, `CryptUnprotectData`, browser/Discord token paths, and embedded webhooks. |
| **Persistence & Evasion** | Registry `Run` keys, `schtasks`, `IsDebuggerPresent`, `AmsiScanBuffer`, `EtwEventWrite`, hidden PowerShell commands. |
| **IOC Extraction** | Extracts ASCII & UTF-16LE embedded URLs, public IPv4 addresses, and SHA-256 hash. |

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

### Scan a single `.exe` or `.dll`
```bash
java -jar dist/binshield.jar C:\path\to\program.exe
```

### Recursively scan a folder for `.exe`, `.dll`, and `.sys`
```bash
java -jar dist/binshield.jar scan ./downloads
```

### JSON output for automation / CI
```bash
java -jar dist/binshield.jar scan sample.dll --json
```

---

## Project Structure

```text
binshield/
├── LICENSE
├── README.md
└── src/com/dips/binshield/
    ├── Main.java
    ├── PeParser.java
    ├── PeHeader.java
    ├── PeSection.java
    ├── Entropy.java
    ├── StringExtractor.java
    ├── RuleEngine.java
    ├── ScanReport.java
    └── Reporter.java
```

---

## Note

`binshield` performs **static heuristic analysis** and does not replace a full antivirus or sandboxed dynamic analysis. Legitimate packed installers or game anti-cheats may trigger high-entropy or anti-debug findings.

## License

Released under the [MIT License](LICENSE).
