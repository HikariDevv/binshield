package com.dips.binshield;

import com.dips.binshield.ScanReport.Finding;
import com.dips.binshield.ScanReport.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class RuleEngine {
    private static final String[] PACKER_SECTIONS = {
        "UPX0", "UPX1", "UPX2", ".vmp0", ".vmp1", ".themida", ".aspack", ".mpress", ".enigma", ".nsp0", ".petite"
    };

    private static final String[] INJECTION_APIS = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "RtlCreateUserThread"
    };

    private static final String[] KEYLOGGER_APIS = {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
        "GetKeyState", "GetClipboardData", "AttachThreadInput"
    };

    private static final String[] SCREEN_SPY_APIS = {
        "BitBlt", "CreateCompatibleBitmap", "GetDC", "capCreateCaptureWindowA", "capCreateCaptureWindowW"
    };

    private static final String[] STEALER_INDICATORS = {
        "CryptUnprotectData", "Login Data", "Local State", "wallet.dat",
        "discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot",
        "\\Discord\\Local Storage", "\\Google\\Chrome\\User Data", "\\BraveSoftware\\",
        "\\Exodus\\exodus.wallet", "\\Electrum\\wallets", "metamask", "tdata"
    };

    private static final String[] DEFENDER_TAMPER = {
        "AmsiScanBuffer", "EtwEventWrite", "Add-MpPreference", "Set-MpPreference",
        "ExclusionPath", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring"
    };

    private static final String[] PERSISTENCE_INDICATORS = {
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce", "schtasks /create",
        "CreateServiceA", "CreateServiceW", "\\Start Menu\\Programs\\Startup"
    };

    private static final String[] EVASION_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "VirtualProtect", "VirtualProtectEx"
    };

    private static final String[] DOWNLOAD_EXEC_INDICATORS = {
        "powershell -enc", "powershell -e ", "powershell.exe -w hidden", "-windowstyle hidden",
        "DownloadString", "Invoke-Expression", "URLDownloadToFileA", "URLDownloadToFileW",
        "certutil -urlcache", "bitsadmin /transfer"
    };

    private RuleEngine() {
    }

    public static ScanReport scan(Path file) throws IOException {
        long start = System.nanoTime();
        byte[] data = Files.readAllBytes(file);
        String sha256 = Entropy.sha256(data);
        double fileEntropy = Entropy.shannon(data, 0, data.length);
        Optional<PeHeader> peOpt = PeParser.parse(data);

        List<Finding> findings = new ArrayList<>();
        int score = 0;

        Set<String> importedFunctions = new HashSet<>();
        if (peOpt.isPresent()) {
            PeHeader pe = peOpt.get();
            for (List<String> fns : pe.imports().values()) {
                for (String fn : fns) {
                    importedFunctions.add(fn.toLowerCase(Locale.ROOT));
                }
            }

            for (PeSection sec : pe.sections()) {
                if (sec.isRwx()) {
                    findings.add(new Finding(Severity.CRITICAL, "T1027", "RWX PE Section",
                            sec.name() + " has Read+Write+Execute (" + sec.flagsString() + ")", 30));
                    score += 30;
                }
                if (sec.entropy() >= 7.25 && sec.rawSize() >= 4096) {
                    findings.add(new Finding(Severity.HIGH, "T1027.002", "High Section Entropy",
                            String.format(Locale.US, "%s entropy %.2f (packed/encrypted)", sec.name(), sec.entropy()), 22));
                    score += 22;
                }
                for (String packer : PACKER_SECTIONS) {
                    if (sec.name().equalsIgnoreCase(packer)) {
                        findings.add(new Finding(Severity.HIGH, "T1027.002", "Known Packer",
                                "Packer/obfuscator section: " + sec.name(), 24));
                        score += 24;
                    }
                }
            }

            PeSection epSec = pe.entryPointSection();
            if (epSec != null && !pe.isDll()) {
                String epName = epSec.name().toLowerCase(Locale.ROOT);
                if (epSec.isWritable() || (!epName.equals(".text") && !epName.equals("code") && !epName.equals(".code"))) {
                    findings.add(new Finding(Severity.HIGH, "T1027.002", "Unusual Entry Point",
                            "EntryPoint inside " + epSec.name() + " (" + epSec.flagsString() + ")", 18));
                    score += 18;
                }
            }

            if (!pe.isSigned() && pe.overlaySize() >= 16384 && pe.overlayEntropy() >= 7.0) {
                findings.add(new Finding(Severity.HIGH, "T1027.009", "Suspicious PE Overlay",
                        String.format(Locale.US, "%d bytes appended after PE (entropy %.2f)", pe.overlaySize(), pe.overlayEntropy()), 22));
                score += 22;
            }

            boolean hasDynLoad = (importedFunctions.contains("loadlibrarya") || importedFunctions.contains("loadlibraryw"))
                    && importedFunctions.contains("getprocaddress");
            int totalImports = pe.totalImportedFunctions();
            if (hasDynLoad && totalImports > 0 && totalImports <= 18 && !pe.isDotNet()) {
                findings.add(new Finding(Severity.HIGH, "T1027.007", "Dynamic API Stub",
                        "LoadLibrary + GetProcAddress with only " + totalImports + " total imports", 22));
                score += 22;
            }

            score += checkImportGroup(importedFunctions, INJECTION_APIS, Severity.CRITICAL, "T1055", "Process Injection (IAT)", 2, 34, findings);
            score += checkImportGroup(importedFunctions, KEYLOGGER_APIS, Severity.HIGH, "T1056.001", "Keylogger / Hook (IAT)", 2, 24, findings);
            score += checkImportGroup(importedFunctions, SCREEN_SPY_APIS, Severity.MEDIUM, "T1113", "Screen Capture (IAT)", 3, 16, findings);
            score += checkImportGroup(importedFunctions, EVASION_APIS, Severity.MEDIUM, "T1622", "Anti-Debug / Memory Prot (IAT)", 3, 14, findings);
        } else if (fileEntropy >= 7.5 && data.length >= 8192) {
            findings.add(new Finding(Severity.MEDIUM, "T1027", "High File Entropy",
                    String.format(Locale.US, "Overall entropy %.2f", fileEntropy), 15));
            score += 15;
        }

        List<String> strings = StringExtractor.extract(data, 5);
        List<String> urls = StringExtractor.extractUrls(strings);
        List<String> ips = StringExtractor.extractPublicIps(strings);

        if (importedFunctions.isEmpty()) {
            score += checkStringGroup(strings, INJECTION_APIS, Severity.CRITICAL, "T1055", "Process Injection (Strings)", 2, 30, findings);
            score += checkStringGroup(strings, KEYLOGGER_APIS, Severity.HIGH, "T1056.001", "Keylogger / Hook (Strings)", 2, 22, findings);
        }

        score += checkStringGroup(strings, STEALER_INDICATORS, Severity.CRITICAL, "T1555", "Credential / Token Stealer", 1, 32, findings);
        score += checkStringGroup(strings, DEFENDER_TAMPER, Severity.CRITICAL, "T1562.001", "Security / AMSI Tampering", 1, 30, findings);
        score += checkStringGroup(strings, PERSISTENCE_INDICATORS, Severity.MEDIUM, "T1547.001", "Persistence Mechanism", 1, 14, findings);
        score += checkStringGroup(strings, DOWNLOAD_EXEC_INDICATORS, Severity.HIGH, "T1059", "Hidden Command / Downloader", 1, 22, findings);

        for (String url : urls) {
            String low = url.toLowerCase(Locale.ROOT);
            if (low.contains("discord.com/api/webhooks") || low.contains("discordapp.com/api/webhooks") || low.contains("api.telegram.org/bot")) {
                findings.add(new Finding(Severity.CRITICAL, "T1041", "Exfiltration Webhook", url, 36));
                score += 36;
                break;
            }
        }

        if (ips.size() >= 4) {
            findings.add(new Finding(Severity.MEDIUM, "T1071", "Embedded Network IOCs",
                    ips.size() + " public IPv4 addresses embedded", 12));
            score += 12;
        }

        if (peOpt.isPresent() && peOpt.get().isSigned() && score > 0 && score < 60) {
            score = Math.max(0, score - 12);
        }

        double elapsedMs = (System.nanoTime() - start) / 1_000_000.0;
        return new ScanReport(file, data.length, sha256, fileEntropy, peOpt.orElse(null), findings, urls, ips, score, elapsedMs);
    }

    private static int checkImportGroup(Set<String> imports,
                                        String[] indicators,
                                        Severity severity,
                                        String technique,
                                        String category,
                                        int minMatches,
                                        int points,
                                        List<Finding> out) {
        Set<String> matched = new LinkedHashSet<>();
        for (String ind : indicators) {
            if (imports.contains(ind.toLowerCase(Locale.ROOT))) {
                matched.add(ind);
            }
        }
        if (matched.size() >= minMatches) {
            out.add(new Finding(severity, technique, category, String.join(", ", matched), points));
            return points;
        }
        return 0;
    }

    private static int checkStringGroup(List<String> strings,
                                        String[] indicators,
                                        Severity severity,
                                        String technique,
                                        String category,
                                        int minMatches,
                                        int points,
                                        List<Finding> out) {
        Set<String> matched = new LinkedHashSet<>();
        for (String s : strings) {
            String lower = s.toLowerCase(Locale.ROOT);
            for (String ind : indicators) {
                if (lower.contains(ind.toLowerCase(Locale.ROOT))) {
                    matched.add(ind);
                }
            }
        }
        if (matched.size() >= minMatches) {
            out.add(new Finding(severity, technique, category, String.join(", ", matched), points));
            return points;
        }
        return 0;
    }
}
