package com.aixcc.widoco.harnesses.one;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import widoco.WidocoUtils;

public class WidocoOne {
    public static void fuzzerTestOneInput(byte[] b) {
        new WidocoOne().fuzz(b);
    }

    public void fuzz(byte[] b) {
        Path dir = null;
        try {
            dir = Files.createTempDirectory("WidocoOne");
            try (ByteArrayInputStream bais = new ByteArrayInputStream(b)) {
                ZipInputStream zis = new ZipInputStream(bais);
                WidocoUtils.unZipIt(zis, dir.toString());
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
        } finally {
            if (dir != null) {
                try {
                    Files.delete(dir);
                } catch (IOException e) {}
            }
        }
    }
}
