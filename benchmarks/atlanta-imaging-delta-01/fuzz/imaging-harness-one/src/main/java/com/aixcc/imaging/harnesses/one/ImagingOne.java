package com.aixcc.imaging.harnesses.one;

import java.io.IOException;

import java.nio.file.Path;
import java.util.HexFormat;

import org.apache.commons.imaging.Imaging;

public class ImagingOne {
    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        //System.out.println("Fuzzing with " + input.length + " bytes");
        try {
            Imaging.getBufferedImage(input);
        } catch (Exception e) {
            // Ignore
            //System.out.println("Exception: " + e.getMessage());
        }
    }

    public static byte[] readInput(Path corpusDir, String seedId) throws IOException {
        // Open file to read the content
        Path seedPath = corpusDir.resolve(seedId);
        return java.nio.file.Files.readAllBytes(seedPath);
    }

    public static byte[] getDummyInput() {
        String imageData = "89504e470d0a1a0a0000000d4948445200000001000000010100000000376ef9240000000a4944415478016360000000020001737501180000000049454e44ae426082";
        // Need to hex decode the input
        return HexFormat.of().parseHex(imageData);
    }

    public static void main(String[] args) throws Exception {
        byte[] input;
        if (args.length == 2) {
            input = readInput(Path.of(args[0]), args[1]);
        } else {
            input = getDummyInput();
        }
        System.out.println("Sending image with " + input.length + " bytes");
        fuzzerTestOneInput(input);
        System.out.println("Parsing done");
    }
}
