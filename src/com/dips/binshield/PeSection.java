package com.dips.binshield;

public final class PeSection {
    private static final int IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private static final int IMAGE_SCN_MEM_READ = 0x40000000;
    private static final int IMAGE_SCN_MEM_WRITE = 0x80000000;

    private final String name;
    private final int virtualAddress;
    private final int virtualSize;
    private final int rawSize;
    private final int rawOffset;
    private final int characteristics;
    private final double entropy;

    public PeSection(String name,
                     int virtualAddress,
                     int virtualSize,
                     int rawSize,
                     int rawOffset,
                     int characteristics,
                     double entropy) {
        this.name = name;
        this.virtualAddress = virtualAddress;
        this.virtualSize = virtualSize;
        this.rawSize = rawSize;
        this.rawOffset = rawOffset;
        this.characteristics = characteristics;
        this.entropy = entropy;
    }

    public String name() {
        return name;
    }

    public int virtualAddress() {
        return virtualAddress;
    }

    public int virtualSize() {
        return virtualSize;
    }

    public int rawSize() {
        return rawSize;
    }

    public int rawOffset() {
        return rawOffset;
    }

    public double entropy() {
        return entropy;
    }

    public boolean containsRva(int rva) {
        long uRva = rva & 0xFFFFFFFFL;
        long start = virtualAddress & 0xFFFFFFFFL;
        long span = Math.max(virtualSize & 0xFFFFFFFFL, rawSize & 0xFFFFFFFFL);
        return uRva >= start && uRva < start + span;
    }

    public boolean isReadable() {
        return (characteristics & IMAGE_SCN_MEM_READ) != 0;
    }

    public boolean isWritable() {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    public boolean isExecutable() {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    public boolean isRwx() {
        return isReadable() && isWritable() && isExecutable();
    }

    public String flagsString() {
        return (isReadable() ? "R" : "-")
                + (isWritable() ? "W" : "-")
                + (isExecutable() ? "X" : "-");
    }
}
