package com.aixcc.batik.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.image.JPEGTranscoder;

import java.net.URL;

public class BatikOne {
    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        try {
            new BatikOne().fuzz(data);
        } catch (FuzzerSecurityIssueLow |
                 FuzzerSecurityIssueMedium |
                 FuzzerSecurityIssueHigh |
                 FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {
        }
    }

    void fuzz(byte[] data) throws Throwable {
        if (data.length < 4) {
            return;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        int picker = buffer.getInt();
        switch (picker) {
            case 94:
                test_jpegtranscoder(buffer);
                break;
            default:
                break;
        }
        
        
    }

    void test_jpegtranscoder(ByteBuffer buffer) throws Throwable {
        Path tempFilePath = Files.createTempFile("output", "jpg");
        File tempFile = tempFilePath.toFile();
        tempFile.deleteOnExit();
        byte[] data = getRemainingAsByte(buffer);      
        try {
            JPEGTranscoder t = new JPEGTranscoder();
            t.addTranscodingHint(JPEGTranscoder.KEY_EXECUTE_ONLOAD, Boolean.TRUE);
            t.addTranscodingHint(JPEGTranscoder.KEY_ALLOWED_SCRIPT_TYPES, "application/java-archive,");
            ByteArrayInputStream stream = new ByteArrayInputStream(data);
            TranscoderInput input = new TranscoderInput(stream);
            input.setURI("file:///");
            FileOutputStream fos = new FileOutputStream(tempFile);
            TranscoderOutput output = new TranscoderOutput(fos);
            t.transcode(input, output);
            fos.close();
        } finally {
            if (tempFilePath != null && Files.exists(tempFilePath)) {
                Files.delete(tempFilePath);
            }
        }
    }

    byte[] getRemainingAsByte(ByteBuffer buffer) {
        byte[] remainingBytes = new byte[buffer.remaining()];
        buffer.get(remainingBytes);
        return remainingBytes;
    }
}
