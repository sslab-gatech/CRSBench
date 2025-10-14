package com.aixcc.activemq.harnesses.one;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.activemq.command.Command;
import org.apache.activemq.openwire.OpenWireFormat;

public class ActivemqOne {
    /**
     * Fuzzing entry point for OpenWireFormat.unmarshal method.
     *
     * @param input the fuzzed input bytes
     */
    public static void fuzzerTestOneInput(byte[] input) {
        if (input.length < 1) return;

        try {
            int version = (int) input[0];
            byte[] rest = new byte[input.length - 1];
            System.arraycopy(input, 1, rest, 0, rest.length);

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

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Please provide a single filename as argument.");
            System.exit(1);
        }

        String filename = args[0];
        try {
            byte[] data = Files.readAllBytes(Paths.get(filename));
            fuzzerTestOneInput(data);
        } catch (IOException e) {
            System.err.println("Failed to read file: " + filename);
            e.printStackTrace();
            System.exit(1);
        }
    }
}