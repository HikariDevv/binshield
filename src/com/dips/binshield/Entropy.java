package com.dips.binshield;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class Entropy {
    private Entropy() {
    }

    public static double shannon(byte[] data, int offset, int length) {
        if (length <= 0 || offset < 0 || offset >= data.length) {
            return 0.0;
        }
        int end = Math.min(data.length, offset + length);
        int actual = end - offset;
        if (actual <= 0) {
            return 0.0;
        }

        int[] freq = new int[256];
        for (int i = offset; i < end; i++) {
            freq[data[i] & 0xFF]++;
        }

        double entropy = 0.0;
        double total = actual;
        for (int count : freq) {
            if (count > 0) {
                double p = count / total;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }

    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
