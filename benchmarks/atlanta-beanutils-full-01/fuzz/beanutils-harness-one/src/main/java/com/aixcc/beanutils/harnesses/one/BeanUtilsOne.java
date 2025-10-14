package com.aixcc.beanutils.harnesses.one;

import java.util.*;
import java.nio.*;
import java.io.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;

import org.apache.commons.beanutils.BeanUtilsBean;
import org.apache.commons.beanutils.BeanUtilsBean2;
import org.apache.commons.beanutils.PropertyUtilsBean;
import java.beans.PropertyDescriptor;
import java.lang.ClassLoader;
import java.lang.Package;
import java.lang.reflect.Constructor;

public class BeanUtilsOne {

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
            1 + // property name minimum
            1 + // separator
            1 + // class name minimum
            1 + // separator
            1 + // constructor type minimum
            1 + // separator
            1; // command minimum

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        new BeanUtilsOne().fuzz(input);
    }

    private void fuzz(byte[] data) {
        try{
            ByteBuffer buf = ByteBuffer.wrap(data);
            int count = buf.getInt();
            System.err.println("count: " + count);
    
            if (count > 255)
                return;
    
            for (int i = 0; i < count; i++) {
                int picker = buf.getInt();
                System.err.println("picker: " + picker);
                try {
                    switch (picker) {
                        case 21: {
                             int data_size = buf.getInt();
                             byte[] inner_data = new byte[data_size];
                             buf.get(inner_data);
                             String whole = new String(inner_data);
    
                             String[] parts = whole.split("\0");
    
    
                             if (parts.length != 4) {
                                 return;
                             }
                             BeanUtilsBean.setInstance(new BeanUtilsBean2());
                             BeanUtilsBean bub = new BeanUtilsBean();
                             PropertyUtilsBean pb = bub.getPropertyUtils();
    
                             ClassLoader a = (ClassLoader) pb.getNestedProperty(pb, parts[0]);
                             Class c = a.loadClass(parts[1]);
                             Constructor con = c.getConstructor(a.loadClass(parts[2]));
    
                             File f = (File) con.newInstance(parts[3]);
                             Scanner s = new Scanner(f);
                             break;
                        }
    
                        default:
                            throw new Exception("unsupported method picker");
                    }
                } catch (Exception e) {
                    continue; // eat it
                }
            }
        } catch (Exception e) {
            return;
        }
    }

    public static byte[] readInput(Path corpusDir, String seedId) throws IOException {
        // Open file to read the content
        Path seedPath = corpusDir.resolve(seedId);
        return java.nio.file.Files.readAllBytes(seedPath);
    }

    public static byte[] getDummyInput() {
        return "a:b:c:d".getBytes();
    }

}
