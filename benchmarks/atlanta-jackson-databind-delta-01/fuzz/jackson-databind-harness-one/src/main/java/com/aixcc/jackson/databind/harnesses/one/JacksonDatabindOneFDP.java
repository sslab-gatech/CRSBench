package com.aixcc.jackson.databind.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonMappingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;

public class JacksonDatabindOneFDP {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
        new JacksonDatabindOneFDP().fuzz(data);
    }

    public void fuzz(FuzzedDataProvider data) throws Throwable {
        if (data.remainingBytes() < Integer.BYTES) {
            return;
        }

        int count = data.consumeInt();
        if (count > 255) {
            return;
        }

        ObjectMapper om = null;
        String filePath = "";

        for (int i = 0; i < count; i++) {
            if (data.remainingBytes() < Integer.BYTES * 2) {
                return;
            }
            int picker = data.consumeInt();
            int buf_size = data.consumeInt();

            if (data.remainingBytes() < buf_size || buf_size < 0) {
                return;
            }
            byte[] whole = data.consumeBytes(buf_size);
            
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
                        try {
                            om.readValue(whole, JacksonDatabindOneDao.class);
                        } catch (JsonMappingException e) {
                            if (e.getMessage() == null || !e.getMessage().contains("prevented for security reasons")) {
                                throw e;
                            }
                        }
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
