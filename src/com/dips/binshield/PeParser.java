package com.dips.binshield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class PeParser {
    private static final int IMAGE_FILE_DLL = 0x2000;

    private PeParser() {
    }

    public static Optional<PeHeader> parse(byte[] data) {
        if (data.length < 64) {
            return Optional.empty();
        }
        if (data[0] != 'M' || data[1] != 'Z') {
            return Optional.empty();
        }

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int peOffset = buf.getInt(0x3C);
        if (peOffset < 0 || peOffset + 24 > data.length) {
            return Optional.empty();
        }
        if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0) {
            return Optional.empty();
        }

        int coffOffset = peOffset + 4;
        int machine = buf.getShort(coffOffset) & 0xFFFF;
        int numberOfSections = buf.getShort(coffOffset + 2) & 0xFFFF;
        long timeDateStamp = buf.getInt(coffOffset + 4) & 0xFFFFFFFFL;
        int sizeOfOptionalHeader = buf.getShort(coffOffset + 16) & 0xFFFF;
        int characteristics = buf.getShort(coffOffset + 18) & 0xFFFF;

        String arch = switch (machine) {
            case 0x014C -> "x86 (32-bit)";
            case 0x8664 -> "x64 (64-bit)";
            case 0xAA64 -> "ARM64";
            default -> String.format("0x%04X", machine);
        };

        boolean isDll = (characteristics & IMAGE_FILE_DLL) != 0;
        int optOffset = coffOffset + 20;
        int entryPoint = 0;
        String subsystem = "Unknown";

        if (sizeOfOptionalHeader >= 70 && optOffset + sizeOfOptionalHeader <= data.length) {
            int magic = buf.getShort(optOffset) & 0xFFFF;
            entryPoint = buf.getInt(optOffset + 16);
            int subVal = (magic == 0x20B || magic == 0x10B) ? (buf.getShort(optOffset + 68) & 0xFFFF) : 0;
            subsystem = switch (subVal) {
                case 1 -> "Native / Driver";
                case 2 -> "Windows GUI";
                case 3 -> "Windows Console";
                default -> "Subsystem " + subVal;
            };
        }

        List<PeSection> sections = new ArrayList<>();
        int sectionTableOffset = optOffset + sizeOfOptionalHeader;
        for (int i = 0; i < numberOfSections; i++) {
            int sOff = sectionTableOffset + (i * 40);
            if (sOff + 40 > data.length) {
                break;
            }
            String name = readSectionName(data, sOff);
            int virtualSize = buf.getInt(sOff + 8);
            int rawSize = buf.getInt(sOff + 16);
            int rawPointer = buf.getInt(sOff + 20);
            int secChars = buf.getInt(sOff + 36);
            double secEntropy = Entropy.shannon(data, rawPointer, rawSize);
            sections.add(new PeSection(name, virtualSize, rawSize, rawPointer, secChars, secEntropy));
        }

        return Optional.of(new PeHeader(arch, isDll, Instant.ofEpochSecond(timeDateStamp), subsystem, entryPoint, sections));
    }

    private static String readSectionName(byte[] data, int offset) {
        int len = 0;
        while (len < 8 && data[offset + len] != 0) {
            len++;
        }
        return new String(data, offset, len, StandardCharsets.US_ASCII).trim();
    }
}
