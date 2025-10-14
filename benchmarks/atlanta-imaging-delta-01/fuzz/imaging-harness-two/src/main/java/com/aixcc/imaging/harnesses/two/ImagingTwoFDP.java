package com.aixcc.imaging.harnesses.two;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.commons.imaging.Imaging;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;

public class ImagingTwoFDP {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        //System.out.println("Fuzzing with " + data.remainingBytes() + " bytes");
        try {
            Imaging.getImageInfo(data.consumeRemainingAsBytes());
        } catch (Exception e) {
            // Ignore
            //System.out.println("Exception: " + e.getMessage());
        }
    }
}
