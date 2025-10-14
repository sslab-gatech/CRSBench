package com.aixcc.cxf.harnesses.three;

import java.util.*;
import java.nio.*;
import java.io.*;
import java.net.*;

import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.ExchangeImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;

import org.apache.cxf.jaxrs.model.wadl.WadlGenerator;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.apache.cxf.jaxrs.impl.ResponseImpl;

import org.mockito.Mockito;
import org.mockito.ArgumentMatchers;
import static org.mockito.Mockito.*;

// To call protected method doFilter w/o restriction for the mock message
class WadlGenerator2 extends WadlGenerator {
    public void filter(ContainerRequestContext context, Message m) {
        doFilter(context, m);
    }
}

public class CXFThree {

    public static void fuzzerTestOneInput(byte[] input) throws Exception {
        String whole = new String(input);
        String[] parts = whole.split("\0");

        if (parts.length != 3) {
            return;
        }

        WadlGenerator2 w = new WadlGenerator2();
        w.setStylesheetReference("reference");

        Message mockM = Mockito.mock(Message.class);
        doReturn(parts[0]).when(mockM).get(Message.HTTP_REQUEST_METHOD);
        //when(mockM.get(Message.HTTP_REQUEST_METHOD)).thenReturn(parts[0]);

        Exchange mockE = Mockito.mock(Exchange.class);
        //when(mockE.getBus()).thenReturn(null);
        doReturn(null).when(mockE).getBus();
        //when(mockM.getExchange()).thenReturn(mockE);
        doReturn(mockE).when(mockM).getExchange();


        MultivaluedMap<String, String> mockMvm = Mockito.mock(MultivaluedMap.class);
        //when(mockMvm.containsKey("_wadl")).thenReturn("0".equals(parts[1]));
        doReturn("0".equals(parts[1])).when(mockMvm).containsKey("_wadl");

        UriInfo mockU = Mockito.mock(UriInfo.class);
        //when(mockU.getQueryParameters()).thenReturn(mockMvm);
        doReturn(mockMvm).when(mockU).getQueryParameters();
        //when(mockU.getPath(false)).thenReturn(parts[2]);
        doReturn(parts[2]).when(mockU).getPath(false);

        ContainerRequestContext mockC = Mockito.mock(ContainerRequestContext.class);
        //when(mockC.getUriInfo()).thenReturn(mockU);
        doReturn(mockU).when(mockC).getUriInfo();

        doAnswer(invocation -> {

            ResponseImpl r = (ResponseImpl) invocation.getArgument(0);
            if (r == null) {
                return null;
            }
            Object e = r.getEntity();
            if (e == null) {
                return null;
            }
            if ("java.io.BufferedInputStream".equals(e.getClass().getName())) {
                BufferedInputStream bis = (BufferedInputStream) r.getEntity();
                byte[] b = new byte[bis.available()];
                bis.read(b);
                System.out.println("Contents: " + new String(b));
            } else {
                FilterInputStream fis = (FilterInputStream) r.getEntity();
                System.out.println("FIS available " + fis.available());
                byte[] b = new byte[fis.available()];
                fis.read(b);
                System.out.println("Contents: " + new String(b));
            }
            return null;

        }).when(mockC).abortWith(ArgumentMatchers.any(Response.class));

        w.filter(mockC, mockM);
    }
}
