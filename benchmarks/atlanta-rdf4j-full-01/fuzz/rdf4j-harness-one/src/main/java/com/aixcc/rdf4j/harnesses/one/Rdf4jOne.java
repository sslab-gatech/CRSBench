package com.aixcc.rdf4j.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import org.eclipse.rdf4j.common.io.ZipUtil;
import org.eclipse.rdf4j.rio.rdfxml.RDFXMLParser;
import org.eclipse.rdf4j.rio.trix.TriXParser;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class Rdf4jOne {
    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        new Rdf4jOne().fuzz(data);
    }

    public void fuzz(byte[] data) throws Throwable {
        if (data.length < Integer.BYTES + Integer.BYTES + 1) {
            return;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        int picker = buf.getInt();
        int count = buf.getInt();
        byte[] whole = Arrays.copyOfRange(data, Integer.BYTES * 2, data.length);
        if (count > 255) {
            return;
        }

        for (int i = 0; i < count; i++) {
            try {
                switch (picker) {
                    case 3:
                        extract(whole);
                        break;
                    case 5:
                        new RDFXMLParser().parse(new ByteArrayInputStream(whole), "");
                        break;
                    case 6:
                        new TriXParser().parse(new ByteArrayInputStream(whole), "");
                        break;
                    default:
                        throw new Exception("unsupported");
                }
            } catch (FuzzerSecurityIssueLow |
                     FuzzerSecurityIssueMedium |
                     FuzzerSecurityIssueHigh |
                     FuzzerSecurityIssueCritical e) {
                throw e;
            } catch (Throwable e) {
            }
        }
    }

    public void extract(byte[] data) throws Throwable {
        Path tempDir = Files.createTempDirectory("rdf4j-");
        File f = new File(tempDir.toString(), "testnotok.zip");
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
            ZipEntry e = new ZipEntry(new String(data));
            out.putNextEntry(e);
            out.write("hello world".getBytes());
            out.closeEntry();
        }

        ZipFile zf = new ZipFile(f);
        Path extractDir = Files.createTempDirectory("rdf4j-extract-");

        ZipUtil.extract(zf, extractDir.toFile());
    }
}
