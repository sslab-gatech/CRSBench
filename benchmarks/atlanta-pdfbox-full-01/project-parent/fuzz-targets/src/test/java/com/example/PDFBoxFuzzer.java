package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;

import org.junit.jupiter.api.BeforeAll;
import java.util.logging.LogManager;
class PDFBoxFuzzer {

    @BeforeAll
    static void setUp() {
        LogManager.getLogManager().reset();
    }


  @FuzzTest
  void myFuzzTest(FuzzedDataProvider data) {
    byte[] bytes = data.consumeRemainingAsBytes();
    try (PDDocument doc = Loader.loadPDF(bytes)) {
      // no-op
    } catch (Exception e) {
    }
  }
}
