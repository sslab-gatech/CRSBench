package com.aixcc.htmlunit.harnesses.one;

import org.htmlunit.BrowserVersion;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlPage;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;

public class HtmlunitOne {

    private static final String HTML_TEMPLATE = "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "    <title>XSLT Transformation</title>\n" +
            "</head>\n" +
            "<body>\n" +
            "    <div id=\"output\"></div>\n" +
            "    <script>\n" +
            "        function loadXMLString(txt) {\n" +
            "            var parser = new DOMParser();\n" +
            "            return parser.parseFromString(txt, \"text/xml\");\n" +
            "        }\n" +
            "\n" +
            "        var xslText = `{XSL_PLACEHOLDER}`;\n" +
            "\n" +
            "        var xmlText = \"<s></s>\";\n" +
            "\n" +
            "        var xslDoc = loadXMLString(xslText);\n" +
            "        var xmlDoc = loadXMLString(xmlText);\n" +
            "\n" +
            "        if (xslDoc.documentElement.nodeName === \"parsererror\" || xmlDoc.documentElement.nodeName === \"parsererror\") {\n" +
            "            document.getElementById(\"output\").innerHTML = \"Error parsing XML.\";\n" +
            "        } else {\n" +
            "            var xsltProcessor = new XSLTProcessor();\n" +
            "            xsltProcessor.importStylesheet(xslDoc);\n" +
            "            var resultDocument = xsltProcessor.transformToFragment(xmlDoc, document);\n" +
            "            document.getElementById(\"output\").appendChild(resultDocument);\n" +
            "        }\n" +
            "    </script>\n" +
            "</body>\n" +
            "</html>";

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        // Convert the byte array to a string
        String htmlString = new String(input, StandardCharsets.UTF_8);

        // Write the HTML content to a temporary file
        File tempFile = File.createTempFile("test", ".html");
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write(htmlString);
        } catch (Exception e) {
            // Ensure the temporary file is deleted if an exception occurs
            tempFile.delete();
            throw e;
        }

        try {
            // Use WebClient to load the temporary file and print the page's normalized text
            WebClient webClient = new WebClient(BrowserVersion.EDGE);
            HtmlPage page = webClient.getPage(tempFile.toURI().toURL());
            System.out.println(page.asNormalizedText());
        } catch (Exception e) {
            // Eat the java exception since fuzzer does not care them
            //System.out.println(e.getMessage());
        } finally {
            // Ensure the temporary file is deleted
            tempFile.delete();
        }
    }
}
