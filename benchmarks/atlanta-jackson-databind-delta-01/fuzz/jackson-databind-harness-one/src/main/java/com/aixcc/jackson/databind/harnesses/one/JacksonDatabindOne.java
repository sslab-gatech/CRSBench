package com.aixcc.jackson.databind.harnesses.one;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;

public class JacksonDatabindOne {
    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        new JacksonDatabindOne().fuzz(data);
    }

    public void fuzz(byte[] data) throws Throwable {
        int cur = 0;
        ByteBuffer buf = ByteBuffer.wrap(data);

        if (data.length < Integer.BYTES) {
            return;
        }

        int count = buf.getInt(cur);
        cur += Integer.BYTES;
        if (count > 255) {
            return;
        }

        ObjectMapper om = null;
        String filePath = "";

        for (int i = 0; i < count; i++) {
            if (data.length - cur < Integer.BYTES * 2) {
                return;
            }
            int picker = buf.getInt(cur);
            cur += Integer.BYTES;
            int buf_size = buf.getInt(cur);
            cur += Integer.BYTES;

            if (data.length - cur < buf_size || buf_size < 0) {
                return;
            }
            byte[] whole = Arrays.copyOfRange(data, cur, cur + buf_size);
            cur += buf_size;
            
            switch (picker) {
                case 5:
                    write(filePath, whole);
                    break;
                case 60:
                    filePath = new String(whole);
                    break;
                case 150:
                    if (om != null) {
                        om.enableDefaultTyping();
                    }
                    break;
                case 5103:
                    om = new ObjectMapper();
                    break;
                case 10010:
                    if (om != null) {
                        om.readValue(whole, JacksonDatabindOneDao.class);
                    }
                    break;
                default:
                    throw new Exception("unsupported");
            }
        }
    }

    public void write(String p, byte[] data) throws Throwable {
        Path parentDir = Paths.get("/tmp/databind");
        Files.createDirectories(parentDir);
        
        Path dir = Files.createTempDirectory(parentDir, "workdir-");
        dir = dir.toRealPath();
        
        Path outFile = dir.resolve(Paths.get(p)).normalize();
        if (!outFile.startsWith(parentDir) || Files.isDirectory(outFile)) {
            throw new IOException("Invalid path");
        }
        Files.write(outFile, data);
    }
}
