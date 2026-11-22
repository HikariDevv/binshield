package com.dips.binshield;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class PeHeader {
    private final String architecture;
    private final boolean pe64;
    private final boolean dll;
    private final boolean dotNet;
    private final boolean signed;
    private final Instant timestamp;
    private final String subsystem;
    private final int entryPointRva;
    private final int overlaySize;
    private final double overlayEntropy;
    private final List<PeSection> sections;
    private final Map<String, List<String>> imports;

    public PeHeader(String architecture,
                    boolean pe64,
                    boolean dll,
                    boolean dotNet,
                    boolean signed,
                    Instant timestamp,
                    String subsystem,
                    int entryPointRva,
                    int overlaySize,
                    double overlayEntropy,
                    List<PeSection> sections,
                    Map<String, List<String>> imports) {
        this.architecture = architecture;
        this.pe64 = pe64;
        this.dll = dll;
        this.dotNet = dotNet;
        this.signed = signed;
        this.timestamp = timestamp;
        this.subsystem = subsystem;
        this.entryPointRva = entryPointRva;
        this.overlaySize = overlaySize;
        this.overlayEntropy = overlayEntropy;
        this.sections = sections;
        this.imports = imports;
    }

    public String architecture() {
        return architecture;
    }

    public boolean isPe64() {
        return pe64;
    }

    public boolean isDll() {
        return dll;
    }

    public boolean isDotNet() {
        return dotNet;
    }

    public boolean isSigned() {
        return signed;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String subsystem() {
        return subsystem;
    }

    public int entryPointRva() {
        return entryPointRva;
    }

    public int overlaySize() {
        return overlaySize;
    }

    public double overlayEntropy() {
        return overlayEntropy;
    }

    public List<PeSection> sections() {
        return sections;
    }

    public Map<String, List<String>> imports() {
        return imports;
    }

    public int totalImportedFunctions() {
        int count = 0;
        for (List<String> fns : imports.values()) {
            count += fns.size();
        }
        return count;
    }

    public PeSection entryPointSection() {
        for (PeSection sec : sections) {
            if (sec.containsRva(entryPointRva)) {
                return sec;
            }
        }
        return null;
    }
}
