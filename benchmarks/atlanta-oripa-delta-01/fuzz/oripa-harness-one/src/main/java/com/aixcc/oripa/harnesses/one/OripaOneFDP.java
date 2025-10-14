
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
package com.aixcc.oripa.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import oripa.persistence.doc.loader.LoaderXML;

public class OripaOneFDP {
    LoaderXML loader = new LoaderXML();
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
        try {
            new OripaOneFDP().fuzz(data);
        } catch (FuzzerSecurityIssueLow |
                 FuzzerSecurityIssueMedium |
                 FuzzerSecurityIssueHigh |
                 FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {}
    }

    public void fuzz(FuzzedDataProvider data) throws Throwable {
        File file = null;
        try {
            file = File.createTempFile("oripa-", ".xml");
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data.consumeRemainingAsBytes());
            fos.close();
            loader.loadAsDataSet(file.getAbsolutePath());
        } catch (IOException e) {
            // Eat the exception
        } finally {
            if (file != null) {
                file.delete();
            }
        }
    }
}
