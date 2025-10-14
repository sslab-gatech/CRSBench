package com.aixcc.fuzzy.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.IOException;
import java.nio.file.Path;

import me.xdrop.fuzzywuzzy.FuzzySearch;
import me.xdrop.fuzzywuzzy.Config;

public class FuzzyOneFDP {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        try {
            // System.out.println("Fuzzing with " + data.remainingBytes() + " bytes");

            // Split input into three strings, terminated by a null byte
            String[] parts = data.consumeRemainingAsString().split("\0");
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
}
