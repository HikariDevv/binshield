package com.dips.binshield;

import java.nio.file.Path;
import java.util.List;

public final class ScanReport {
    public enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    public record Finding(Severity severity, String category, String detail, int score) {
    }

    private final Path file;
    private final long fileSize;
    private final String sha256;
    private final double fileEntropy;
    private final PeHeader peHeader;
    private final List<Finding> findings;
    private final List<String> urls;
    private final List<String> ips;
    private final int riskScore;
    private final double elapsedMs;

    public ScanReport(Path file,
                      long fileSize,
                      String sha256,
                      double fileEntropy,
                      PeHeader peHeader,
                      List<Finding> findings,
                      List<String> urls,
                      List<String> ips,
                      int riskScore,
                      double elapsedMs) {
        this.file = file;
        this.fileSize = fileSize;
        this.sha256 = sha256;
        this.fileEntropy = fileEntropy;
        this.peHeader = peHeader;
        this.findings = findings;
        this.urls = urls;
        this.ips = ips;
        this.riskScore = Math.min(100, riskScore);
        this.elapsedMs = elapsedMs;
    }

    public Path file() {
        return file;
    }

    public long fileSize() {
        return fileSize;
    }

    public String sha256() {
        return sha256;
    }

    public double fileEntropy() {
        return fileEntropy;
    }

    public PeHeader peHeader() {
        return peHeader;
    }

    public List<Finding> findings() {
        return findings;
    }

    public List<String> urls() {
        return urls;
    }

    public List<String> ips() {
        return ips;
    }

    public int riskScore() {
        return riskScore;
    }

    public double elapsedMs() {
        return elapsedMs;
    }

    public String verdict() {
        if (riskScore >= 65) {
            return "HIGH RISK";
        }
        if (riskScore >= 35) {
            return "SUSPICIOUS";
        }
        if (riskScore >= 15) {
            return "LOW RISK";
        }
        return "CLEAN";
    }
}
