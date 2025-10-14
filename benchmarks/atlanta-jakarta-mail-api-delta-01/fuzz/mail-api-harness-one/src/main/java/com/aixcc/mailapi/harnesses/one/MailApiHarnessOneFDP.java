package com.aixcc.mailapi.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.*;
import java.nio.*;
import java.io.*;

import javax.xml.transform.stream.StreamSource;

import jakarta.mail.internet.MimeMessage;
import jakarta.activation.MailcapCommandMap;

public class MailApiHarnessOneFDP {

    public static void setUp() throws Exception {
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        try {
            byte[] input = data.consumeRemainingAsBytes();
            ByteArrayInputStream bs = new ByteArrayInputStream(input);
    
            MimeMessage mimeMessage = new MimeMessage(null, bs);
    
            // Re-serialize the message, changing the subject.
            mimeMessage = new MimeMessage(mimeMessage);
            mimeMessage.setSubject("FWD: " + mimeMessage.getSubject());
            mimeMessage.setContent(mimeMessage.getDataHandler().getDataSource(), mimeMessage.getContentType());
            mimeMessage.saveChanges();
    
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            mimeMessage.writeTo(bos);
    
            String serialized = new String(bos.toByteArray(), "UTF-8");
        } catch (Exception e) {
            // Ignore exceptions.
        }
    }
}
