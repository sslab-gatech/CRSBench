// Copyright 2022 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.StaxDriver;
import com.thoughtworks.xstream.io.binary.BinaryStreamDriver;
import com.thoughtworks.xstream.io.HierarchicalStreamDriver;

import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.mapper.CannotResolveClassException;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.security.ForbiddenClassException;

import java.io.ByteArrayInputStream;

public class XmlFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        XStream xstream;
        HierarchicalStreamDriver driver;
        switch (data.consumeInt()) {
            case 1:
                driver = new DomDriver();
                break;
            case 2:
                driver = new StaxDriver();
                break;
            case 3:
                driver = new BinaryStreamDriver();
                break;
            case 4:
                driver = null;
                break;
            default:
                return;
        }

        if (driver != null) {
            xstream = new XStream(driver);
        } else {
            xstream = new XStream();
        }

        try {
            if (driver instanceof BinaryStreamDriver) {
                xstream.fromXML(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
            } else {
                xstream.fromXML(data.consumeRemainingAsString());
            }
        } catch (Exception e) {
            // Do nothing.
        }
    }
}