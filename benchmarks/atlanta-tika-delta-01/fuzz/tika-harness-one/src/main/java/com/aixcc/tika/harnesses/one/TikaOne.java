package com.aixcc.tika.harnesses.one;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.tika.cli.TikaCLI;
import org.apache.tika.exception.TikaException;

public class TikaOne {

    static {
        System.setProperty("jazzer.fs_allowed_dirs",
                System.getProperty("java.io.tmpdir") +
                ",/tmp," +
                System.getProperty("user.dir"));
    }

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        // write the input to a temporary file
        File tmpFile = File.createTempFile("tika-harness-one", "");

        try {
            FileOutputStream fos = new FileOutputStream(tmpFile);
            fos.write(input);
            fos.close();
            // run Tika on the temporary file
            System.err.println("Start running Tika on " + tmpFile.getAbsolutePath() + " with " + input.length + " bytes");
            TikaCLI.main(new String[] { "--extract", tmpFile.getAbsolutePath() });
            System.err.println("Finished running Tika on " + tmpFile.getAbsolutePath() + " with " + input.length + " bytes");

        } catch (IOException e) {
            // eat io exception

        } catch (TikaException e) {
            // eat tika exception

        } finally {
            // delete the temporary file
            if (tmpFile.exists()) {
                tmpFile.delete();
            }
        }

    }

}
