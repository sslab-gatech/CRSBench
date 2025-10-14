package com.aixcc.activemq.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.activemq.command.Command;
import org.apache.activemq.openwire.OpenWireFormat;

public class ActivemqVariantOneFDP {
    /**
     * Fuzzing entry point for OpenWireFormat.unmarshal method.
     *
     * @param data the fuzzed input FuzzedDataProvider
     */
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        if (data.remainingBytes() < 1) return;

        try {
            int version = (int) data.consumeByte();
            byte[] rest = data.consumeRemainingAsBytes();

            // Initialize the OpenWireFormat with the desired version
            OpenWireFormat format = new OpenWireFormat();

            // Set the version 
            if (version < 1 || version > 12)
                return;
            format.setVersion(version);

            // Create a DataInputStream from the fuzzed input bytes
            DataInputStream dataIn = new DataInputStream(new ByteArrayInputStream(rest));

            // Attempt to unmarshal the input
            Command command = (Command) format.unmarshal(dataIn);

            // Optionally, process the command or check its properties
            // For fuzzing, this may not be necessary
        } catch (Exception e) {
            // Catch and handle any exceptions to prevent the fuzzer from stopping
            // Log the exception if needed
            System.err.println("Exception during unmarshal: " + e.getMessage());
        }
    }
}
