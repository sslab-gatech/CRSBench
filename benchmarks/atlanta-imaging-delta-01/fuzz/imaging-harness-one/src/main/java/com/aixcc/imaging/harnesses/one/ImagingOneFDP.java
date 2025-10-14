package com.aixcc.imaging.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.IOException;

import java.nio.file.Path;
import java.util.HexFormat;

import org.apache.commons.imaging.Imaging;

public class ImagingOneFDP {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        //System.out.println("Fuzzing with " + data.remainingBytes() + " bytes");
        try {
            Imaging.getBufferedImage(data.consumeRemainingAsBytes());
        } catch (Exception e) {
            // Ignore
            //System.out.println("Exception: " + e.getMessage());
        }
    }
}
