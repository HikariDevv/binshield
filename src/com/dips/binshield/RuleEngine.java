package com.dips.binshield;

import com.dips.binshield.ScanReport.Finding;
import com.dips.binshield.ScanReport.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public final class RuleEngine {
    private static final String[] PACKER_SECTIONS = {
        "UPX0", "UPX1", "UPX2", ".vmp0", ".vmp1", ".themida", ".aspack", ".mpress", ".enigma", ".nsp0"
    };

    private static final String[] INJECTION_APIS = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "ResumeThread"
    };

    private static final String[] KEYLOGGER_APIS = {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
        "GetKeyState", "GetForegroundWindow", "AttachThreadInput"
    };

    private static final String[] STEALER_INDICATORS = {
        "CryptUnprotectData", "Login Data", "Local State", "wallet.dat",
        "discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot",
        "\\Discord\\Local Storage", "\\Google\\Chrome\\User Data"
    };

    private static final String[] PERSISTENCE_INDICATORS = {
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce", "schtasks",
        "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW"
    };

    private static final String[] EVASION_INDICATORS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "VirtualProtect", "AmsiScanBuffer", "EtwEventWrite"
    };

    private static final String[] SHELL_INDICATORS = {
        "powershell -enc", "powershell -e ", "powershell.exe -w hidden",
        "cmd.exe /c", "URLDownloadToFileA", "URLDownloadToFileW", "ShellExecuteA", "ShellExecuteW"
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

        if (peOpt.isPresent()) {
            PeHeader pe = peOpt.get();
            for (PeSection sec : pe.sections()) {
                if (sec.isRwx()) {
                    findings.add(new Finding(Severity.CRITICAL, "PE Section", "RWX section detected: " + sec.name() + " (" + sec.flagsString() + ")", 28));
                    score += 28;
                }
                if (sec.entropy() >= 7.25 && sec.rawSize() >= 4096) {
                    findings.add(new Finding(Severity.HIGH, "Packing / Encryption", String.format(Locale.US, "High entropy in %s (%.2f)", sec.name(), sec.entropy()), 20));
                    score += 20;
                }
                for (String packer : PACKER_SECTIONS) {
                    if (sec.name().equalsIgnoreCase(packer)) {
                        findings.add(new Finding(Severity.HIGH, "Packer", "Known packer/obfuscator section: " + sec.name(), 22));
                        score += 22;
                    }
                }
            }
        } else if (fileEntropy >= 7.5 && data.length >= 8192) {
            findings.add(new Finding(Severity.MEDIUM, "Entropy", String.format(Locale.US, "High overall file entropy (%.2f)", fileEntropy), 15));
            score += 15;
        }

        List<String> strings = StringExtractor.extract(data, 5);
        List<String> urls = StringExtractor.extractUrls(strings);
        List<String> ips = StringExtractor.extractPublicIps(strings);

        score += checkIndicatorGroup(strings, INJECTION_APIS, Severity.CRITICAL, "Process Injection", 2, 30, findings);
        score += checkIndicatorGroup(strings, KEYLOGGER_APIS, Severity.HIGH, "Keylogger / Input Hook", 2, 24, findings);
        score += checkIndicatorGroup(strings, STEALER_INDICATORS, Severity.CRITICAL, "Credential / Token Stealer", 1, 30, findings);
        score += checkIndicatorGroup(strings, PERSISTENCE_INDICATORS, Severity.MEDIUM, "Persistence", 1, 14, findings);
        score += checkIndicatorGroup(strings, EVASION_INDICATORS, Severity.MEDIUM, "Anti-Debug / Evasion", 2, 16, findings);
        score += checkIndicatorGroup(strings, SHELL_INDICATORS, Severity.HIGH, "Command Execution / Downloader", 1, 18, findings);

        for (String url : urls) {
            String low = url.toLowerCase(Locale.ROOT);
            if (low.contains("discord.com/api/webhooks") || low.contains("discordapp.com/api/webhooks") || low.contains("api.telegram.org/bot")) {
                findings.add(new Finding(Severity.CRITICAL, "Exfiltration Endpoint", "Embedded webhook/bot URL: " + url, 35));
                score += 35;
                break;
            }
        }

        if (ips.size() >= 3) {
            findings.add(new Finding(Severity.MEDIUM, "Network IOC", ips.size() + " embedded public IP addresses found", 12));
            score += 12;
        }

        double elapsedMs = (System.nanoTime() - start) / 1_000_000.0;
        return new ScanReport(file, data.length, sha256, fileEntropy, peOpt.orElse(null), findings, urls, ips, score, elapsedMs);
    }

    private static int checkIndicatorGroup(List<String> strings,
                                           String[] indicators,
                                           Severity severity,
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
            out.add(new Finding(severity, category, "Matched: " + String.join(", ", matched), points));
            return points;
        }
        return 0;
    }
}
