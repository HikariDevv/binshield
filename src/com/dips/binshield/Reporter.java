package com.dips.binshield;

import com.dips.binshield.ScanReport.Finding;
import com.dips.binshield.ScanReport.Severity;

import java.util.Locale;

public final class Reporter {
    private Reporter() {
    }

    public static void printText(ScanReport report, boolean color) {
        String reset = color ? "\033[0m" : "";
        String bold = color ? "\033[1m" : "";
        String dim = color ? "\033[2m" : "";

        System.out.println();
        System.out.println("  " + bold + "binshield — static PE analysis" + reset);
        System.out.println("  File     : " + report.file().getFileName() + " (" + formatBytes(report.fileSize()) + ")");
        System.out.println("  SHA-256  : " + report.sha256());
        System.out.printf(Locale.US, "  Entropy  : %.2f / 8.00%n", report.fileEntropy());

        PeHeader pe = report.peHeader();
        if (pe != null) {
            System.out.println("  PE Type  : " + (pe.isDll() ? "DLL" : "EXE") + " · " + pe.architecture() + " · " + pe.subsystem());
            System.out.println("  Compiled : " + pe.timestamp());
            System.out.println();
            System.out.println("  " + dim + String.format("%-10s %-10s %-10s %-6s %s", "SECTION", "RAW_SIZE", "VIRT_SIZE", "FLAGS", "ENTROPY") + reset);
            for (PeSection sec : pe.sections()) {
                String warn = (sec.isRwx() || sec.entropy() >= 7.25) && color ? "\033[1;31m" : "";
                System.out.printf(Locale.US, "  %s%-10s %-10d %-10d %-6s %.2f%s%n",
                        warn, sec.name(), sec.rawSize(), sec.virtualSize(), sec.flagsString(), sec.entropy(), warn.isEmpty() ? "" : reset);
            }
        } else {
            System.out.println("  PE Type  : Not a valid Windows PE binary");
        }

        System.out.println();
        if (report.findings().isEmpty()) {
            System.out.println("  " + (color ? "\033[1;32m" : "") + "No suspicious indicators detected." + reset);
        } else {
            System.out.println("  " + bold + "Findings (" + report.findings().size() + "):" + reset);
            for (Finding f : report.findings()) {
                String col = color ? severityColor(f.severity()) : "";
                System.out.printf("  %s[%-8s]%s %-28s %s (+%d)%n",
                        col, f.severity().name(), reset, f.category(), f.detail(), f.score());
            }
        }

        if (!report.urls().isEmpty()) {
            System.out.println();
            System.out.println("  " + dim + "Embedded URLs (showing up to 5 of " + report.urls().size() + "):" + reset);
            report.urls().stream().limit(5).forEach(u -> System.out.println("    - " + u));
        }

        if (!report.ips().isEmpty()) {
            System.out.println();
            System.out.println("  " + dim + "Embedded Public IPs (showing up to 5 of " + report.ips().size() + "):" + reset);
            report.ips().stream().limit(5).forEach(ip -> System.out.println("    - " + ip));
        }

        String vColor = color ? verdictColor(report.riskScore()) : "";
        System.out.println();
        System.out.printf(Locale.US, "  Verdict  : %s%s (%d/100)%s  %s[%.1f ms]%s%n%n",
                vColor, report.verdict(), report.riskScore(), reset, dim, report.elapsedMs(), reset);
    }

    public static void printJson(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"file\": \"").append(escape(report.file().toString())).append("\",\n");
        sb.append("  \"size\": ").append(report.fileSize()).append(",\n");
        sb.append("  \"sha256\": \"").append(report.sha256()).append("\",\n");
        sb.append(String.format(Locale.US, "  \"entropy\": %.2f,\n", report.fileEntropy()));
        sb.append("  \"risk_score\": ").append(report.riskScore()).append(",\n");
        sb.append("  \"verdict\": \"").append(report.verdict()).append("\",\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < report.findings().size(); i++) {
            Finding f = report.findings().get(i);
            sb.append("    {\"severity\": \"").append(f.severity().name())
                    .append("\", \"category\": \"").append(escape(f.category()))
                    .append("\", \"detail\": \"").append(escape(f.detail()))
                    .append("\", \"score\": ").append(f.score()).append("}")
                    .append(i + 1 < report.findings().size() ? ",\n" : "\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        System.out.println(sb);
    }

    private static String severityColor(Severity s) {
        return switch (s) {
            case CRITICAL -> "\033[1;31m";
            case HIGH -> "\033[1;33m";
            case MEDIUM -> "\033[1;36m";
            case LOW -> "\033[0;37m";
        };
    }

    private static String verdictColor(int score) {
        if (score >= 65) {
            return "\033[1;31m";
        }
        if (score >= 35) {
            return "\033[1;33m";
        }
        return "\033[1;32m";
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        String[] units = {"KB", "MB", "GB"};
        double val = bytes;
        int idx = -1;
        while (val >= 1024 && idx < units.length - 1) {
            val /= 1024.0;
            idx++;
        }
        return String.format(Locale.US, "%.2f %s", val, units[idx]);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
