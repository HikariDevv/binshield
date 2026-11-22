package com.dips.binshield;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class PeParser {
    private static final int IMAGE_FILE_DLL = 0x2000;

    private PeParser() {
    }

    public static Optional<PeHeader> parse(byte[] data) {
        if (data.length < 64 || data[0] != 'M' || data[1] != 'Z') {
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
        boolean pe64 = false;
        boolean signed = false;
        boolean dotNet = false;
        int importDirRva = 0;

        if (sizeOfOptionalHeader >= 96 && optOffset + sizeOfOptionalHeader <= data.length) {
            int magic = buf.getShort(optOffset) & 0xFFFF;
            pe64 = (magic == 0x20B);
            entryPoint = buf.getInt(optOffset + 16);
            int subVal = buf.getShort(optOffset + 68) & 0xFFFF;
            subsystem = switch (subVal) {
                case 1 -> "Native / Driver";
                case 2 -> "Windows GUI";
                case 3 -> "Windows Console";
                default -> "Subsystem " + subVal;
            };

            int dataDirOffset = optOffset + (pe64 ? 112 : 96);
            int numRvaAndSizes = buf.getInt(optOffset + (pe64 ? 108 : 92));
            if (numRvaAndSizes >= 2 && dataDirOffset + 16 <= data.length) {
                importDirRva = buf.getInt(dataDirOffset + 8);
            }
            if (numRvaAndSizes >= 5 && dataDirOffset + 40 <= data.length) {
                int certOffset = buf.getInt(dataDirOffset + 32);
                int certSize = buf.getInt(dataDirOffset + 36);
                signed = certOffset > 0 && certSize > 0 && certOffset + certSize <= data.length;
            }
            if (numRvaAndSizes >= 15 && dataDirOffset + 120 <= data.length) {
                int clrRva = buf.getInt(dataDirOffset + 112);
                int clrSize = buf.getInt(dataDirOffset + 116);
                dotNet = clrRva > 0 && clrSize > 0;
            }
        }

        List<PeSection> sections = new ArrayList<>();
        int sectionTableOffset = optOffset + sizeOfOptionalHeader;
        int maxSectionEnd = 0;

        for (int i = 0; i < numberOfSections; i++) {
            int sOff = sectionTableOffset + (i * 40);
            if (sOff + 40 > data.length) {
                break;
            }
            String name = readSectionName(data, sOff);
            int virtualSize = buf.getInt(sOff + 8);
            int virtualAddress = buf.getInt(sOff + 12);
            int rawSize = buf.getInt(sOff + 16);
            int rawPointer = buf.getInt(sOff + 20);
            int secChars = buf.getInt(sOff + 36);
            double secEntropy = Entropy.shannon(data, rawPointer, rawSize);
            sections.add(new PeSection(name, virtualAddress, virtualSize, rawSize, rawPointer, secChars, secEntropy));
            if (rawPointer > 0 && rawSize > 0) {
                maxSectionEnd = Math.max(maxSectionEnd, rawPointer + rawSize);
            }
        }

        int overlaySize = 0;
        double overlayEntropy = 0.0;
        if (maxSectionEnd > 0 && maxSectionEnd < data.length) {
            overlaySize = data.length - maxSectionEnd;
            if (!signed && overlaySize > 0) {
                overlayEntropy = Entropy.shannon(data, maxSectionEnd, overlaySize);
            }
        }

        Map<String, List<String>> imports = parseImports(data, buf, sections, importDirRva, pe64);
        return Optional.of(new PeHeader(
                arch,
                pe64,
                isDll,
                dotNet,
                signed,
                Instant.ofEpochSecond(timeDateStamp),
                subsystem,
                entryPoint,
                overlaySize,
                overlayEntropy,
                sections,
                imports
        ));
    }

    private static Map<String, List<String>> parseImports(byte[] data,
                                                          ByteBuffer buf,
                                                          List<PeSection> sections,
                                                          int importDirRva,
                                                          boolean pe64) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        if (importDirRva <= 0) {
            return map;
        }
        int descOffset = rvaToOffset(importDirRva, sections);
        if (descOffset < 0) {
            return map;
        }

        for (int i = 0; i < 128; i++) {
            int off = descOffset + (i * 20);
            if (off + 20 > data.length) {
                break;
            }
            int origFirstThunk = buf.getInt(off);
            int nameRva = buf.getInt(off + 12);
            int firstThunk = buf.getInt(off + 16);
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) {
                break;
            }

            int dllNameOff = rvaToOffset(nameRva, sections);
            if (dllNameOff < 0) {
                continue;
            }
            String dllName = readCString(data, dllNameOff, 128);
            if (dllName.isEmpty()) {
                continue;
            }

            int thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            int thunkOff = rvaToOffset(thunkRva, sections);
            List<String> functions = new ArrayList<>();
            if (thunkOff >= 0) {
                int entrySize = pe64 ? 8 : 4;
                for (int j = 0; j < 2048; j++) {
                    int tOff = thunkOff + (j * entrySize);
                    if (tOff + entrySize > data.length) {
                        break;
                    }
                    long entry = pe64 ? buf.getLong(tOff) : (buf.getInt(tOff) & 0xFFFFFFFFL);
                    if (entry == 0L) {
                        break;
                    }
                    boolean isOrdinal = pe64 ? (entry < 0) : ((entry & 0x80000000L) != 0);
                    if (isOrdinal) {
                        functions.add("Ordinal#" + (entry & 0xFFFFL));
                    } else {
                        int hintNameOff = rvaToOffset((int) (entry & 0x7FFFFFFFL), sections);
                        if (hintNameOff >= 0 && hintNameOff + 2 < data.length) {
                            String fnName = readCString(data, hintNameOff + 2, 128);
                            if (!fnName.isEmpty()) {
                                functions.add(fnName);
                            }
                        }
                    }
                }
            }
            map.put(dllName, functions);
        }
        return map;
    }

    private static int rvaToOffset(int rva, List<PeSection> sections) {
        long uRva = rva & 0xFFFFFFFFL;
        for (PeSection sec : sections) {
            if (sec.containsRva(rva)) {
                long delta = uRva - (sec.virtualAddress() & 0xFFFFFFFFL);
                long fileOff = (sec.rawOffset() & 0xFFFFFFFFL) + delta;
                if (fileOff >= 0 && fileOff < Integer.MAX_VALUE) {
                    return (int) fileOff;
                }
            }
        }
        return -1;
    }

    private static String readSectionName(byte[] data, int offset) {
        int len = 0;
        while (len < 8 && data[offset + len] != 0) {
            len++;
        }
        return new String(data, offset, len, StandardCharsets.US_ASCII).trim();
    }

    private static String readCString(byte[] data, int offset, int maxLen) {
        int len = 0;
        while (offset + len < data.length && len < maxLen && data[offset + len] != 0) {
            int c = data[offset + len] & 0xFF;
            if (c < 0x20 || c > 0x7E) {
                break;
            }
            len++;
        }
        return new String(data, offset, len, StandardCharsets.US_ASCII);
    }
}
