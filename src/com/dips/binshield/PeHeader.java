package com.dips.binshield;

import java.time.Instant;
import java.util.List;

public final class PeHeader {
    private final String architecture;
    private final boolean dll;
    private final Instant timestamp;
    private final String subsystem;
    private final int entryPointRva;
    private final List<PeSection> sections;

    public PeHeader(String architecture, boolean dll, Instant timestamp, String subsystem, int entryPointRva, List<PeSection> sections) {
        this.architecture = architecture;
        this.dll = dll;
        this.timestamp = timestamp;
        this.subsystem = subsystem;
        this.entryPointRva = entryPointRva;
        this.sections = sections;
    }

    public String architecture() {
        return architecture;
    }

    public boolean isDll() {
        return dll;
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

    public List<PeSection> sections() {
        return sections;
    }
}
