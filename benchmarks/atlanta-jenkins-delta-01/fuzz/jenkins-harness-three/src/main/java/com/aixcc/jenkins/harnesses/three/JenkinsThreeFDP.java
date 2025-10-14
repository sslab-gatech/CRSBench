package com.aixcc.jenkins.harnesses.three;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import static org.mockito.Mockito.*;

import aixcc.util.StaplerReplacer;

import hudson.PluginManager;
import hudson.ProxyConfiguration;
import hudson.model.FreeStyleBuild;
import hudson.model.Job;
import hudson.security.AccessDeniedException3;

import io.jenkins.plugins.toyplugin.Script;
import io.jenkins.plugins.toyplugin.AccessFilter;
import io.jenkins.plugins.toyplugin.Api;
import io.jenkins.plugins.toyplugin.AuthAction;
import io.jenkins.plugins.coverage.CoverageProcessor;
import io.jenkins.plugins.toyplugin.SecretMessage;
import io.jenkins.plugins.toyplugin.Script;
import io.jenkins.plugins.toyplugin.StateMonitor;
import io.jenkins.plugins.toyplugin.UserNameAction;
import io.jenkins.plugins.toyplugin.UserRemoteConfig;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import javax.naming.NamingException;
import javax.servlet.ReadListener;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import jenkins.model.Jenkins;

import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.*;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import com.code_intelligence.jazzer.api.BugDetectors;

public class JenkinsThreeFDP {

    static Jenkins jenkins;
    static StaplerReplacer replacer;
    static PluginManager manager;
    static ResponseImpl rsp;
    static SecretMessage secretMessage;

    public static void fuzzerInitialize() throws Throwable {
        jenkins = Mockito.mock(Jenkins.class);

        replacer = new StaplerReplacer();
        replacer.setWebApp(new WebApp(Mockito.mock(ServletContext.class)));

        rsp = Mockito.mock(ResponseImpl.class);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        when(rsp.getWriter()).thenReturn(pw);

        secretMessage = new SecretMessage();
        manager = PluginManager.createDefault(jenkins);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
	BugDetectors.allowNetworkConnections((host, port) -> host.equals("localhost"));
        new JenkinsThreeFDP().fuzz(data);
    }

    public void fuzz(FuzzedDataProvider data) throws Exception {
        if (data.remainingBytes() < 4) {
            return;
        }

        int picker = data.consumeInt();
	    System.err.println("000 " + picker);
        switch (picker) {
            case 11:
                testProxyConfiguration(data);
                break;
            case 33:
                testPlugin(data);
                break;
            case 37:
                testScript(data);
                break;
            case 38:
                testStateMonitor(data);
                break;
            case 73:
                testApi(data);
                break;
            case 77:
                testAccessFilter(data);
                break;
            case 142:
                testUserNameAction(data);
                break;
            case 144:
                testRecoverCoverage(data);
                break;
            case 190:
                testAuthAction(data);
                break;
            case 209:
                testSecretMessage(data);
                break;
            case 249:
                testUserRemoteConfig(data);
                break;
            default:
                break;
        }

    }

    void testProxyConfiguration(FuzzedDataProvider data) throws Exception {
        Authentication a = Mockito.mock(Authentication.class);
        when(a.getName()).thenReturn("mock");

        Jenkins j = Mockito.mock(Jenkins.class);
        doThrow(new AccessDeniedException3(a, Jenkins.ADMINISTER))
            .when(j)
            .checkPermission(Jenkins.ADMINISTER);

        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 5) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        try {
            new ProxyConfiguration.DescriptorImpl2(j).doValidateProxy(parts[4], req, rsp);
        } catch (AccessDeniedException3 | InterruptedException e) {}
    }

    void testRecoverCoverage(FuzzedDataProvider data) throws Exception {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 2)
            return;

        String reportName = parts[0];
        if (reportName.contains("..")) {
            return;
        }

        String serializedObject = parts[1];
        if (!reportName.startsWith("coverage")) {
            return;
        }

        byte[] target = null;
        try {
            target = java.util.Base64.getDecoder().decode(serializedObject);
        } catch (IllegalArgumentException e) {
            return;
        }

        FreeStyleBuild build = Mockito.mock(FreeStyleBuild.class);
        File tmpDir = Files.createTempDirectory("testRecoverCoverage").toFile();
        try {
            File reportFile = new File(tmpDir, reportName);
            try (FileOutputStream fos = new FileOutputStream(reportFile)) {
                fos.write(target);
            } catch (IOException e) {
                return;
            }
            when(build.getRootDir()).thenReturn(tmpDir);
            CoverageProcessor.recoverCoverageResult(build); } catch (SecurityException e) {
        } finally {
            try {
                if (tmpDir.exists()) {
                    FileUtils.deleteDirectory(tmpDir);
                }
            } catch (IOException e) {}
        }
    }

    void testUserNameAction(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 4) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        try {
            new UserNameAction().doGetName(req, rsp);
        } catch (IOException e) {}
    }

    void testStateMonitor(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 4) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        try {
            new StateMonitor().doCheck(req, rsp);
        } catch (Exception e) {
        }
    }

    void testUserRemoteConfig(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 2) {
            return;
        }

        try {
            UserRemoteConfig userRemoteConfig = new UserRemoteConfig();
            Method method = UserRemoteConfig.class.getMethod(parts[0], String.class);
            method.invoke(userRemoteConfig, parts[1]);
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {}
    }

    void testAuthAction(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 4) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);

        AuthAction action = new AuthAction();
        try {
            action.authenticateAsAdmin(req, rsp);
        } catch (IOException | NamingException e) {}
    }

    void testApi(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 3) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        try {
            new Api(jenkins).doXml(req, rsp, parts[2], null, null, 0);
        } catch (IOException | ServletException e) {}
    }

    void testSecretMessage(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 8) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        when(innerReq.getParameter(parts[4])).thenReturn(parts[5]);
        when(innerReq.getParameter(parts[6])).thenReturn(parts[7]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        when(jenkins.hasPermission(Jenkins.ADMINISTER)).thenReturn(false);
        secretMessage.setJenkins(jenkins);
        try {
            secretMessage.doPerform(req, rsp);
        } catch (IOException e) {}
    }

    void testAccessFilter(FuzzedDataProvider data) {
        String[] parts = data.consumeRemainingAsString().split("\0");
        if (parts.length != 4) {
            return;
        }

        HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
        when(innerReq.getParameter(parts[0])).thenReturn(parts[1]);
        when(innerReq.getParameter(parts[2])).thenReturn(parts[3]);
        RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
        when(jenkins.hasPermission(Jenkins.ADMINISTER)).thenReturn(false);
        AccessFilter accessFilter = new AccessFilter();
        accessFilter.setJenkins(jenkins);
        try {
            accessFilter.doGet(req, rsp);
        } catch (IOException e) {}
    }

    void testScript(FuzzedDataProvider data) {
        when(jenkins.hasPermission(Job.CONFIGURE)).thenReturn(true);
        try {
            String whole = data.consumeRemainingAsString();
            new Script(jenkins).doCheckScriptCompile(whole);
        } catch (Exception e) {}
        when(jenkins.hasPermission(Job.CONFIGURE)).thenReturn(false);

    }

    void testPlugin(FuzzedDataProvider data) {
        try {
            int numRequests = data.consumeByte() % 10;

            for (int i = 0; i < numRequests; i++) {
                int method = data.consumeByte() % 2;
                HttpServletRequest innerReq = Mockito.mock(HttpServletRequest.class);
                int numParams = data.consumeByte() % 10;
                for (int j = 0; j < numParams; j++) {
                    int paramNameLen = data.consumeShort();
                    String paramName = data.consumeString(paramNameLen);
                    int valueLen = data.consumeShort();
                    String value = data.consumeString(valueLen);
                    when(innerReq.getParameter(paramName)).thenReturn(value);
                }

                boolean setContentType = data.consumeBoolean();
                if (setContentType) {
                    int contentTypeLen = data.consumeShort();
                    String contentType = data.consumeString(contentTypeLen);
                    when(innerReq.getContentType()).thenReturn(contentType);
                }

                if (data.consumeBoolean()) {
                    int bodyLength = data.consumeShort();
                    byte[] body = data.consumeBytes(bodyLength);
                    ByteArrayInputStream byteStream = new ByteArrayInputStream(body);
                    when(innerReq.getInputStream()).thenAnswer(input -> {
                        return new DelegatingServletInputStream(byteStream);
                    });
                    when(innerReq.getContentLength()).thenReturn(bodyLength);
                }

                RequestImpl req = new RequestImpl(replacer.stapler, innerReq, Collections.emptyList(), null);
                if (method == 0) {
                    HttpResponse res = manager.doCreateNewUpload(req);
                } else if (method == 1) {
                    HttpResponse res = manager.doPerformUpload(req);
                }
            }
        } catch (Exception e) {}
    }

    public static class DelegatingServletInputStream extends ServletInputStream {

        private final InputStream sourceStream;

        /**
         * Create a DelegatingServletInputStream for the given source stream.
         * @param sourceStream the source stream (never <code>null</code>)
         */
        public DelegatingServletInputStream(InputStream sourceStream) {
            this.sourceStream = sourceStream;
        }

        /**
         * Return the underlying source stream (never <code>null</code>).
         */
        public final InputStream getSourceStream() {
            return this.sourceStream;
        }

        public int read() throws IOException {
            return this.sourceStream.read();
        }

        public void close() throws IOException {
            super.close();
            this.sourceStream.close();
        }

        public boolean isFinished() {
            try {
                return this.sourceStream.available() == 0;
            } catch (IOException e) {
                return true;
            }
        }

        public boolean isReady() {
            return true;
        }

        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException();
        }
    }
}
