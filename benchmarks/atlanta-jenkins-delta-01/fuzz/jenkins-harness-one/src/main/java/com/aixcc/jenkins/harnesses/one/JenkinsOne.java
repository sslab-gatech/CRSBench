package com.aixcc.jenkins.harnesses.one;

import static org.mockito.Mockito.*;

import aixcc.util.StaplerReplacer;
import io.jenkins.plugins.toyplugin.UserRemoteConfig;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.Collections;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.kohsuke.stapler.*;
import org.mockito.Mockito;

public class JenkinsOne {

    static ResponseImpl response;
    static StaplerReplacer replacer;
    static UserRemoteConfig urc;

    public static void fuzzerInitialize() throws Throwable {
        replacer = new StaplerReplacer();
        replacer.setWebApp(new WebApp(Mockito.mock(ServletContext.class)));

        HttpServletResponse inner_response = Mockito.mock(HttpServletResponse.class);
        PrintWriter writer = new PrintWriter(new StringWriter());
        when(inner_response.getWriter()).thenReturn(writer);

        response = new ResponseImpl(replacer.stapler, inner_response);
        replacer.setCurrentResponse(response);

        urc = new UserRemoteConfig();
    }

    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        new JenkinsOne().fuzz(data);
    }

    public void fuzz(byte[] data) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(data);
        if (buf.remaining() < 4) {
            return;
        }

        int picker = buf.getInt();
        switch (picker) {
            case 24:
                testUrcModCounter_1(buf);
                break;
            case 98:
                testUrcModCounter_2(buf);
                break;
            default:
                break;
        }
    }

    void testUrcModCounter_1(ByteBuffer buf) throws Exception {
        HttpServletRequest inner_request = Mockito.mock(HttpServletRequest.class);
        String remaining = getRemainingAsString(buf);
        String[] parts = remaining.split(":");
        if (parts.length < 3 && parts.length % 3 != 0) {
            return;
        }
        for (int i = 0; i < parts.length; i += 3) {
            when(inner_request.getParameter("cmd")).thenReturn(parts[i]);
            when(inner_request.getParameter("value")).thenReturn(parts[i + 1]);
            when(inner_request.getParameter("checksum")).thenReturn(parts[i + 2]);
            RequestImpl request =
                    new RequestImpl(replacer.stapler, inner_request, Collections.emptyList(), null);
            urc.modCounter(request, response);
        }
        urc.incCounter();
    }

    void testUrcModCounter_2(ByteBuffer buf) throws Exception {
        HttpServletRequest inner_request = Mockito.mock(HttpServletRequest.class);
        if (buf.remaining() < 4) {
            return;
        }
        int command_count = buf.getInt();
        for (int i = 0; i < command_count; ++i) {
            if (buf.remaining() < 4) {
                return;
            }
            int command = buf.getInt();
            switch (command) {
                case 0:
                    if (buf.remaining() < 12) {
                        return;
                    }
                    String cmd = Integer.toString(buf.getInt());
                    when(inner_request.getParameter("cmd")).thenReturn(cmd);
                    String value = Integer.toString(buf.getInt());
                    when(inner_request.getParameter("value")).thenReturn(value);
                    String checksum = Integer.toString(buf.getInt());
                    when(inner_request.getParameter("checksum")).thenReturn(checksum);
                    RequestImpl request =
                            new RequestImpl(replacer.stapler, inner_request, Collections.emptyList(), null);
                    urc.modCounter(request, response);
                    break;
                case 1:
                    urc.incCounter();
                    break;
            }
        }
    }

    String getRemainingAsString(ByteBuffer buf) {
        byte[] remainingBytes = new byte[buf.remaining()];
        buf.get(remainingBytes);
        return new String(remainingBytes);
    }
}
