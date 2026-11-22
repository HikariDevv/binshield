package com.dips.binshield;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class StringExtractor {
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{6,}");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b");

    private StringExtractor() {
    }

    public static List<String> extract(byte[] data, int minLength) {
        Set<String> strings = new LinkedHashSet<>();
        StringBuilder ascii = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c <= 0x7E) {
                ascii.append((char) c);
            } else {
                if (ascii.length() >= minLength) {
                    strings.add(ascii.toString());
                }
                ascii.setLength(0);
            }
        }
        if (ascii.length() >= minLength) {
            strings.add(ascii.toString());
        }

        StringBuilder utf16 = new StringBuilder();
        for (int i = 0; i + 1 < data.length; i += 2) {
            int lo = data[i] & 0xFF;
            int hi = data[i + 1] & 0xFF;
            if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
                utf16.append((char) lo);
            } else {
                if (utf16.length() >= minLength) {
                    strings.add(utf16.toString());
                }
                utf16.setLength(0);
            }
        }
        if (utf16.length() >= minLength) {
            strings.add(utf16.toString());
        }

        return new ArrayList<>(strings);
    }

    public static List<String> extractUrls(List<String> strings) {
        Set<String> urls = new LinkedHashSet<>();
        for (String s : strings) {
            Matcher m = URL_PATTERN.matcher(s);
            while (m.find()) {
                urls.add(m.group());
            }
        }
        return new ArrayList<>(urls);
    }

    public static List<String> extractPublicIps(List<String> strings) {
        Set<String> ips = new LinkedHashSet<>();
        for (String s : strings) {
            Matcher m = IP_PATTERN.matcher(s);
            while (m.find()) {
                String ip = m.group();
                if (!isIgnoredIp(ip)) {
                    ips.add(ip);
                }
            }
        }
        return new ArrayList<>(ips);
    }

    private static boolean isIgnoredIp(String ip) {
        return ip.startsWith("0.")
                || ip.startsWith("127.")
                || ip.startsWith("255.")
                || ip.startsWith("192.168.")
                || ip.startsWith("10.")
                || ip.equals("1.0.0.0")
                || ip.equals("2.0.0.0");
    }
}
