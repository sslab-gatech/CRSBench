package com.aixcc.tika.harnesses.two;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.apache.tika.metadata.Metadata;

import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.external.CompositeExternalParser;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.html.JSoupParser;

import org.xml.sax.ContentHandler;
import org.xml.sax.helpers.DefaultHandler;

// Note: this harness requires the installation of a real `exiftool` to trigger
//         since the tika default external parser will not be initialized without that installation
public class TikaTwo {

    public static void fuzzerTestOneInput(byte[] input) throws Exception {

        InputStream stream = new BufferedInputStream(new ByteArrayInputStream(input));

        // null metadata indicates html content type for JSoupParser
        Metadata metadata = new Metadata();
        
        ContentHandler handler = new DefaultHandler();

        ParseContext context = new ParseContext();
        context.set(Parser.class, new CompositeExternalParser());

        (new JSoupParser()).parse(stream, handler, metadata, context);

        for (String name : metadata.names()) {
            System.out.println(name + ": " + metadata.get(name));
        }

    }
}
