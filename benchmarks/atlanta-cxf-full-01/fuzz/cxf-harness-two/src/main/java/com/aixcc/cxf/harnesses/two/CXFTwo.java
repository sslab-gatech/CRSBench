package com.aixcc.cxf.harnesses.two;

import java.util.*;
import java.nio.*;
import java.io.*;

import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.ExchangeImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.message.XMLMessage;
import org.apache.cxf.aegis.type.mtom.AttachmentUtil;
import org.apache.cxf.attachment.AttachmentImpl;

import javax.activation.DataHandler;

public class CXFTwo {
    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        String whole = new String(input);
        String[] parts = whole.split("\0");

        if (parts.length != 2) {
            return;
        }

        ArrayList<Attachment> list = new ArrayList<Attachment>();
        AttachmentImpl ai = new AttachmentImpl(parts[0]);
        list.add(ai);

        Attachment a = AttachmentUtil.getAttachment(parts[1], list);

        DataHandler d = a.getDataHandler();

        d.getContentType();
    }
}
