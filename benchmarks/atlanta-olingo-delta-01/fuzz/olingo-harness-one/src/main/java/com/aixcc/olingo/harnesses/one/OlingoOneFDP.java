
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
package com.aixcc.olingo.harnesses.one;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.olingo.client.api.v4.ODataClient;
import org.apache.olingo.client.api.communication.header.ODataPreferences;
import org.apache.olingo.client.api.communication.request.retrieve.ODataEntitySetRequest;
// import org.apache.olingo.client.api.communication.request.v4.AsyncRequestWrapper;
// import org.apache.olingo.client.api.communication.response.v4.AsyncResponseWrapper;
import org.apache.olingo.client.api.communication.response.ODataResponse;
import org.apache.olingo.commons.api.domain.v4.ODataEntitySet;
import org.apache.olingo.commons.api.edm.constants.ODataServiceVersion;
import org.apache.olingo.client.core.ODataClientFactory;
// import org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl;
// import org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl.AsyncResponseWrapperImpl;
import org.apache.olingo.commons.api.format.ContentType;
import org.apache.olingo.commons.api.format.ODataPubFormat;
// import org.apache.olingo.client.core.communication.request.v4.AsyncRequestFactoryImpl;
import org.apache.olingo.client.api.uri.v4.URIBuilder;

import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Matchers.any;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.*;

import org.apache.http.StatusLine;
import org.apache.http.message.BasicHeader;
import org.apache.http.Header;
import org.apache.http.HttpResponse;

public class OlingoOneFDP {
    final int expected_data_length = Integer.BYTES + // count
            Integer.BYTES + // picker
            +1; // host

    // Global variables to store reflected classes and methods
    private static Class<?> asyncRequestFactoryClass = null;
    private static Constructor<?> asyncRequestFactoryConstructor = null;
    private static Method getAsyncRequestWrapperMethod = null;

    private static Class<?> asyncRequestWrapperImplClass = null;
    private static Constructor<?> asyncResponseWrapperImplConstructor = null;
    private static Method isDoneMethod = null;

    // Initialization function to check for v4 classes and set global variables
    static {
        try {
            // Try to load AsyncRequestFactoryImpl class
            asyncRequestFactoryClass = Class.forName("org.apache.olingo.client.core.communication.request.v4.AsyncRequestFactoryImpl");
            asyncRequestFactoryConstructor = asyncRequestFactoryClass.getConstructor(ODataClient.class);
            // Get the getAsyncRequestWrapper method
            getAsyncRequestWrapperMethod = asyncRequestFactoryClass.getMethod("getAsyncRequestWrapper", org.apache.olingo.client.api.communication.request.ODataRequest.class);

            // Try to load AsyncRequestWrapperImpl class
            asyncRequestWrapperImplClass = Class.forName("org.apache.olingo.client.core.communication.request.v4.AsyncRequestWrapperImpl");
            // Get inner class AsyncResponseWrapperImpl
            Class<?>[] declaredClasses = asyncRequestWrapperImplClass.getDeclaredClasses();
            Class<?> asyncResponseWrapperImplClass = null;
            for (Class<?> innerClass : declaredClasses) {
                if (innerClass.getSimpleName().equals("AsyncResponseWrapperImpl")) {
                    asyncResponseWrapperImplConstructor = innerClass.getDeclaredConstructor(asyncRequestWrapperImplClass, HttpResponse.class);
                    asyncResponseWrapperImplConstructor.setAccessible(true); // In case the constructor is not public
                    // Get the isDone method
                    isDoneMethod = innerClass.getMethod("isDone");
                    asyncResponseWrapperImplClass = innerClass;
                    break;
                }
            }
            if (asyncResponseWrapperImplClass == null) {
                // Inner class not found
                asyncRequestWrapperImplClass = null;
            }
        } catch (ClassNotFoundException e) {
            // v4 classes not present
            System.err.println("v4 classes not found. Async operations will be skipped.");
            asyncRequestFactoryClass = null;
            asyncRequestWrapperImplClass = null;
        } catch (Exception e) {
            e.printStackTrace();
            asyncRequestFactoryClass = null;
            asyncRequestWrapperImplClass = null;
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        try {
            new OlingoOneFDP().fuzz(data);
        } catch (Exception e) {
            // Eat
        }

    }

    private void fuzz(FuzzedDataProvider data) {
        int count = data.consumeInt();
        System.err.println("count:" + count);

        if (count > 255)
            return;

        for (int i = 0; i < count; i++) {
            int picker = data.consumeInt();
            System.err.println("picker: " + picker);

            try {
                switch (picker) {
                    case 97: {
                        // Check if v4 classes are available
                        if (asyncRequestFactoryClass == null || asyncRequestWrapperImplClass == null) {
                            // v4 classes not available, skip this iteration
                            System.err.println("v4 classes not available, skipping.");
                            return;
                        }

                        int data_size = data.consumeInt();
                        String whole = data.consumeString(data_size);

                        String[] parts = whole.split("\0");

                        if (parts.length == 0) {
                            return;
                        }

                        final String url = "http://www.google.com";
                        ODataClient client = ODataClientFactory.getV4();
                        final URIBuilder uriBuilder = client.getURIBuilder(url);

                        final ODataEntitySetRequest<ODataEntitySet> oData = client.getRetrieveRequestFactory().getEntitySetRequest(uriBuilder.build());
                        oData.setFormat(ODataPubFormat.JSON);

                        // Create instance of AsyncRequestFactoryImpl via reflection
                        Object asyncRequestFactory = asyncRequestFactoryConstructor.newInstance(client);
                        // Call getAsyncRequestWrapper method via reflection
                        Object wrappedRequest = getAsyncRequestWrapperMethod.invoke(asyncRequestFactory, oData);
                        // Check if wrappedRequest is instance of AsyncRequestWrapperImpl
                        if (!asyncRequestWrapperImplClass.isInstance(wrappedRequest)) {
                            System.err.println("wrappedRequest is not instance of AsyncRequestWrapperImpl");
                            return;
                        }

                        // Create instance of AsyncResponseWrapperImpl via reflection
                        final HttpResponse httpResponse = Mockito.mock(HttpResponse.class);
                        StatusLine statusLine = Mockito.mock(StatusLine.class);
                        when(httpResponse.getStatusLine()).thenReturn(statusLine);
                        when(statusLine.getStatusCode()).thenReturn(202);

                        Header[] locationHeaders = new Header[] {
                                new BasicHeader("Location", "https://" + parts[0]),
                        };
                        Header[] retryAfterHeaders = new Header[] {
                            new BasicHeader("Retry-After", "3600")
                        };
                        Header[] preferenceAppliedHeaders = new Header[] {
                            new BasicHeader("Preference-Applied", new ODataPreferences(ODataServiceVersion.V40).respondAsync())
                        };

                        when(httpResponse.getHeaders("Location")).thenReturn(locationHeaders);
                        when(httpResponse.getHeaders("Retry-After")).thenReturn(retryAfterHeaders);
                        when(httpResponse.getHeaders("Preference-Applied")).thenReturn(preferenceAppliedHeaders);

                        Object wrappedResponseImpl = asyncResponseWrapperImplConstructor.newInstance(wrappedRequest, httpResponse);

                        // Call isDone method via reflection
                        boolean isDoneResult = (boolean) isDoneMethod.invoke(wrappedResponseImpl);
                        System.out.println("isDone: " + isDoneResult);

                        break;
                    }
                    // Keep other cases unchanged
                    default:
                        // Other cases can be handled here
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
