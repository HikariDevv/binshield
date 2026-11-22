package com.dips.binshield;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

public final class Main {
    private static final String VERSION = "1.0.0";

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help") || args[0].equals("help")) {
            printHelp();
            return;
        }
        if (args[0].equals("-v") || args[0].equals("--version") || args[0].equals("version")) {
            System.out.println("binshield " + VERSION);
            return;
        }

        Path target = null;
        boolean json = false;
        boolean color = true;

        int start = args[0].equalsIgnoreCase("scan") ? 1 : 0;
        for (int i = start; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--json")) {
                json = true;
            } else if (arg.equals("--no-color")) {
                color = false;
            } else if (arg.startsWith("-")) {
                System.err.println("Unknown option: " + arg);
                System.exit(2);
            } else if (target == null) {
                target = Path.of(arg).toAbsolutePath().normalize();
            }
        }

        if (target == null || !Files.exists(target)) {
            System.err.println("Error: target path does not exist.");
            System.exit(2);
        }

        try {
            int exitCode = 0;
            if (Files.isRegularFile(target)) {
                ScanReport report = RuleEngine.scan(target);
                if (json) {
                    Reporter.printJson(report);
                } else {
                    Reporter.printText(report, color);
                }
                if (report.riskScore() >= 35) {
                    exitCode = 1;
                }
            } else if (Files.isDirectory(target)) {
                List<Path> binaries;
                try (Stream<Path> walk = Files.walk(target)) {
                    binaries = walk.filter(Files::isRegularFile)
                            .filter(Main::isBinaryTarget)
                            .toList();
                }
                for (Path bin : binaries) {
                    ScanReport report = RuleEngine.scan(bin);
                    if (json) {
                        Reporter.printJson(report);
                    } else {
                        Reporter.printText(report, color);
                    }
                    if (report.riskScore() >= 35) {
                        exitCode = 1;
                    }
                }
            }
            System.exit(exitCode);
        } catch (Exception e) {
            System.err.println("Fatal: " + e.getMessage());
            System.exit(2);
        }
    }

    private static boolean isBinaryTarget(Path path) {
        String name = path.getFileName().toString().toLowerCase();
        return name.endsWith(".exe") || name.endsWith(".dll") || name.endsWith(".sys");
    }

    private static void printHelp() {
        System.out.println("""
            binshield %s — static PE (.exe/.dll) malware & RAT analyzer

            Usage:
              java -jar binshield.jar scan <file|folder> [--json] [--no-color]
              java -jar binshield.jar <file.exe>
              java -jar binshield.jar version
              java -jar binshield.jar help

            Exit codes:
              0  Clean or low risk
              1  Suspicious or high risk binary detected
              2  Invalid arguments or I/O error
            """.formatted(VERSION));
    }
}
