package com.aixcc.fuzzy.harnesses.one;

import java.io.IOException;
import java.nio.file.Path;

import me.xdrop.fuzzywuzzy.FuzzySearch;
import me.xdrop.fuzzywuzzy.Config;

public class FuzzyOne {
    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        try {
            //System.out.println("Fuzzing with " + input.length + " bytes");

            // Split input into three strings, terminated by a null byte
            String[] parts = new String(input).split("\0");
            if (parts.length < 2) {
                //System.out.println("Invalid input");
                return;
            }

            // Set the config
            int startIndex = 0;
            if (parts.length > 2) {
                Config.setConfig(parts[0]);
                startIndex = 1;
            }

            int r = FuzzySearch.ratio(parts[startIndex], parts[startIndex + 1]);

            //System.out.println("Ratio: " + r);
        } catch (Exception e) {
            //System.out.println("Exception: " + e);
        }
    }

    public static byte[] readInput(Path corpusDir, String seedId) throws IOException {
        // Open file to read the content
        Path seedPath = corpusDir.resolve(seedId);
        return java.nio.file.Files.readAllBytes(seedPath);
    }

    public static byte[] getDummyInput() {
        return "hello\0world".getBytes();
    }

    public static void main(String[] args) throws Exception {
        byte[] input;
        if (args.length == 2) {
            input = readInput(Path.of(args[0]), args[1]);
        } else {
            input = getDummyInput();
        }
        fuzzerTestOneInput(input);
    }
}
