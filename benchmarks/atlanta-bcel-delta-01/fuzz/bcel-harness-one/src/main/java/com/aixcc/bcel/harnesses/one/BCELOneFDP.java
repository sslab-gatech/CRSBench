package com.aixcc.bcel.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;

import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.Repository;
import org.apache.bcel.verifier.Verifier;
import org.apache.bcel.verifier.VerifierFactory;


public class BCELOneFDP {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        try {
            byte[] input = data.consumeRemainingAsBytes();
            ByteArrayInputStream bis = new ByteArrayInputStream(input);
            ClassParser parser = new ClassParser(bis, "Test.class");

            Repository.addClass(parser.parse());

            Verifier verifier = VerifierFactory.getVerifier("Test");
            verifier.doPass1();
            verifier.doPass2();

        } catch (Exception e) {
            // Ignore all exceptions thrown.
        }
    }

}
