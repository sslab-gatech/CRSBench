
// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////
package com.aixcc.kylin.harnesses.one;

import org.apache.kylin.cube.CubeInstance;
import org.apache.kylin.rest.controller.CubeController;
import org.apache.kylin.rest.service.CubeService;
import org.apache.kylin.cube.CubeManager;
import org.apache.kylin.cube.CubeSegment;
import org.apache.kylin.metadata.model.Segments;
import org.apache.kylin.common.KylinConfig;

import org.mockito.MockedStatic;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.nio.ByteBuffer;
import java.util.regex.Pattern;

public class KylinOne {
    final int expected_data_length = Integer.BYTES + // count
            Integer.BYTES + // picker
            1 + // cube name minimum
            1 + // separator
            1 + // backtick
            1 + // project name minimum
            1; // backtick

    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9-_/.\\s]+$");

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        try {
            new KylinOne().fuzz(input);
        } catch (Throwable e) {
        }
    }
    
    private void fuzz(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        int count = buf.getInt();
        System.err.println("count:" + count);

        if (count > 255)
            return;

        for (int i = 0; i < count; i++) {
            int picker = buf.getInt();
            System.err.println("picker: " + picker);

            try {
                switch (picker) {
                    case 33: {
                        int data_size = buf.getInt();
                        byte[] inner_data = new byte[data_size];
                        buf.get(inner_data);
                        String whole = new String(inner_data);

                        String[] parts = whole.split("\0");

                        if (parts.length < 2)
                            return;

                        if (!isValidExecutableInput(parts[1]))
                            return;

                        CubeService cubeService = new CubeService();
                        CubeController cubeController = new CubeController();

                        CubeManager mockCubeManagerInstance = mock(CubeManager.class);
                        CubeInstance mockCubeInstance = mock(CubeInstance.class);
                        Segments<CubeSegment> mockSegments = mock(Segments.class);
                        KylinConfig mockKylinConfig = mock(KylinConfig.class);

                        MockedStatic<KylinConfig> mockKylinConfigStatic = mockStatic(KylinConfig.class);
                        MockedStatic<CubeManager> mockCubeManagerStatic = mockStatic(CubeManager.class);

                        try {
                            mockKylinConfigStatic.when(KylinConfig::getInstanceFromEnv).thenReturn(mockKylinConfig);
                            mockCubeManagerStatic.when(() -> CubeManager.getInstance(any(KylinConfig.class)))
                                    .thenReturn(mockCubeManagerInstance);

                            when(mockCubeManagerInstance.getCube(parts[0])).thenReturn(mockCubeInstance);
                            when(mockCubeInstance.getConfig()).thenReturn(mockKylinConfig);
                            when(mockCubeInstance.getSegments()).thenReturn(mockSegments);
                            when(mockSegments.iterator()).thenReturn(new ArrayList<CubeSegment>().iterator());

                            setKylinConfig(mockKylinConfig);

                            cubeController.setCubeService(cubeService);
                            cubeController.migrateCube(parts[0], parts[1]);
                        } finally {
                            mockKylinConfigStatic.close();
                            mockCubeManagerStatic.close();
                        }
                    }
                }
            } catch (Exception e) {
                continue;
            }
        }
    }

    private static void setKylinConfig(KylinConfig mockKylinConfig) {
        when (mockKylinConfig.isAllowAutoMigrateCube()).thenReturn(true);
        when (mockKylinConfig.getAutoMigrateCubeSrcConfig()).thenReturn("srcConfig");
        when (mockKylinConfig.getAutoMigrateCubeDestConfig()).thenReturn("destConfig");
    }

    public static boolean isValidExecutableInput(String input) {
        if (input.length() < 3 || !input.startsWith("`") || !input.endsWith("`"))
            return false;
        
        String content = input.substring(1, input.length() - 1);
        if (!SAFE_PATTERN.matcher(content).matches() || content.contains("`")) {
            return false;
        }

        int backslashCount = 0;
        for (char ch : content.toCharArray()) {
            if (ch == '\\') {
                backslashCount++;
            }
        }
        return backslashCount % 2 == 0;
    }
    
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

