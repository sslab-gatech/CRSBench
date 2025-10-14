package com.aixcc.ztzip.harnesses.one;

import java.util.*;
import java.nio.*;
import java.io.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Files;

import org.zeroturnaround.zip.ZipUtil;

public class ZTZIPOne {

    public static void main(String[] args) throws Exception {
        byte[] input;
        if (args.length == 2) {
            input = readInput(Path.of(args[0]), args[1]);
        } else {
            input = getDummyInput();
        }
        fuzzerTestOneInput(input);
    }

    final int expected_data_length = Integer.BYTES + // count
        Integer.BYTES + // picker
        1 + // request header name minimum
        1 + // separator
        1 + // request header value minimum
        1 + // separator
        1; // command minimum

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        try {
            new ZTZIPOne().fuzz(input);
        } catch (Throwable e) {
        }
    }

    private void fuzz(byte[] data) {
        if (data == null) {
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        int count = buf.getInt();

        if (count > 255)
            return;

        for (int i = 0; i < count; i++) {
            int picker = buf.getInt();
            try {
                switch (picker) {
                    case 16: {
                         int data_size = buf.remaining();
                         byte[] inner_data = new byte[data_size];
                         buf.get(inner_data);

                         InputStream is = new ByteArrayInputStream(inner_data);
                         Path tempDir = Files.createTempDirectory("ztzip-");
                         ZipUtil.unpack(is, tempDir.toFile());
                         break;
                    }

                    default:
                        throw new Exception("unsupported method picker");
                }
            } catch (Exception e) {
                continue; // eat it
            }
        }
    }

    public static byte[] readInput(Path corpusDir, String seedId) throws IOException {
        // Open file to read the content
        Path seedPath = corpusDir.resolve(seedId);
        return java.nio.file.Files.readAllBytes(seedPath);
    }

    public static byte[] getDummyInput() {
        return "hello_world".getBytes();
    }
}
