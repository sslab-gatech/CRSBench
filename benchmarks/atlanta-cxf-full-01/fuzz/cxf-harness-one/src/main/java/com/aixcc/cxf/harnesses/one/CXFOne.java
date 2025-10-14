package com.aixcc.cxf.harnesses.one;

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
import org.apache.cxf.attachment.AttachmentUtil;

import javax.activation.DataSource;

public class CXFOne {

    private static MessageImpl msg;

    public static void setUp() throws Exception {
        msg = new MessageImpl();
        Exchange exchange = new ExchangeImpl();
        msg.setExchange(exchange);
    }

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        CXFOne.setUp();
        try {
            String contentId = new String(input);
            // set contentId
            DataSource ds = AttachmentUtil.getAttachmentDataSource(contentId, Collections.emptyList());
            // access
            String ct = ds.getContentType();
        }
        catch (Exception e) {
            // eat all exceptions
        }
    }
}
