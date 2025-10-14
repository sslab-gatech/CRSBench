package com.aixcc.kylin.harnesses.one;

public class Main {
    public static void main(String[] args) {
        String cube = "exampleCube";
        String project = "`jazze`";
        
        String input = cube + "\0" + project;
        byte[] data = input.getBytes();

        try {
            KylinOne.fuzzerTestOneInput(data);
            System.out.println("fuzzerTestOneInput executed successfully.");
        } catch (Throwable e) {
            e.printStackTrace();
            System.err.println("Error executing fuzzerTestOneInput: " + e.getMessage());
        }
    }
}

