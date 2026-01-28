package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.util.logging.LogManager;

public class PDFBoxFuzzer {

    static {
        LogManager.getLogManager().reset();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] bytes = data.consumeRemainingAsBytes();
        try (PDDocument doc = Loader.loadPDF(bytes)) {
            // no-op
        } catch (Exception e) {
        }
    }
}
