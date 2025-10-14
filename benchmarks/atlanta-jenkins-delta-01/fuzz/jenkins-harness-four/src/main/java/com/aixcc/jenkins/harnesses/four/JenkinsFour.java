package com.aixcc.jenkins.harnesses.four;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

import aixcc.util.StaplerReplacer;

import hudson.security.Permission;
import jenkins.model.Jenkins;

import org.apache.commons.io.FileUtils;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

import com.sonyericsson.jenkins.plugins.bfa.CauseManagement;
import com.sonyericsson.jenkins.plugins.bfa.PluginImpl;
import com.sonyericsson.jenkins.plugins.bfa.db.LocalFileKnowledgeBase;
import com.sonyericsson.jenkins.plugins.bfa.db.MongoDBKnowledgeBase;
import com.sonyericsson.jenkins.plugins.bfa.model.FailureCause;
import com.sonyericsson.jenkins.plugins.bfa.model.FailureCause.FailureCauseDescriptor;

import org.kohsuke.stapler.*;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.Collections;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class JenkinsFour {

    static StaplerReplacer replacer;
    static ResponseImpl responseImpl = Mockito.mock(ResponseImpl.class);
    static CauseManagement causeManagement = new CauseManagement();
    static FailureCause failureCause;
    static FailureCause.FailureCauseDescriptor failureCauseDescriptor = new FailureCause.FailureCauseDescriptor();

    static Jenkins jenkins;
    static PluginImpl pluginImpl = Mockito.mock(PluginImpl.class);
    static LocalFileKnowledgeBase knowledgeBase = spy(new LocalFileKnowledgeBase());
    static LocalFileKnowledgeBase.LocalFileKnowledgeBaseDescriptor knowledgeBaseDescriptor = new LocalFileKnowledgeBase.LocalFileKnowledgeBaseDescriptor();

    public static void main(String args[]) throws Throwable {
    }

    public static void fuzzerInitialize() throws Throwable {
        Path jenkinsRootDir = Files.createTempDirectory("jenkins-four");
        Files.createDirectories(jenkinsRootDir);
        jenkins = Mockito.mock(Jenkins.class);
        Jenkins.set(new Jenkins.JenkinsHolder() {
            @Override
            public Jenkins getInstance() {
                return jenkins;
            }
        });
        PluginImpl.setInstance(pluginImpl);
        when(jenkins.getDescriptorByType(FailureCauseDescriptor.class)).thenReturn(failureCauseDescriptor);
        when(jenkins.getRootDir()).thenReturn(jenkinsRootDir.toFile());
        when(pluginImpl.getKnowledgeBase()).thenReturn(knowledgeBase);
        replacer = new StaplerReplacer();
        replacer.setWebApp(new WebApp(Mockito.mock(ServletContext.class)));
        replacer.setCurrentResponse(responseImpl);
    }

    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        try {
            new JenkinsFour().fuzz(data);
        } catch (FuzzerSecurityIssueLow | FuzzerSecurityIssueMedium | FuzzerSecurityIssueHigh
                | FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {
        }
    }

    public void fuzz(byte[] data) throws Throwable {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int numRequests = (int) buffer.get();
        if (numRequests < 0)
            return;

        RequestImpl requestImpl = null;
        for (int i = 0; i < numRequests; ++i) {
            int command = (int) buffer.get();
            switch (command) {
                case 5:
                    requestImpl = createHttpRequest(buffer);
                    failureCause = causeManagement.getDynamic(requestImpl.getParameter("id"), requestImpl,
                            responseImpl);
                    failureCause.setId("0");
                    break;
                case 19:
                    setPermission((int) buffer.get());
                    break;
                case 24:
                    requestImpl = createHttpRequest(buffer);
                    causeManagement.doRemoveConfirm(requestImpl.getParameter("id"), requestImpl, responseImpl);
                    break;
                case 33:
                    requestImpl = createHttpRequest(buffer);
                    knowledgeBaseDescriptor.doSave(requestImpl);
                    break;
                case 59:
                    requestImpl = createHttpRequest(buffer);
                    failureCause.doConfigSubmit(requestImpl, responseImpl);
                    break;
                case 63:
                    requestImpl = createHttpRequest(buffer);
                    knowledgeBaseDescriptor.doLoad(requestImpl);
                    break;
                case 87:
                    requestImpl = createHttpRequest(buffer);
                    knowledgeBaseDescriptor.doForceUpdate(requestImpl);
                    break;
                default:
                    break;
            }
        }
    }

    private String readStringUntilNullByte(ByteBuffer buffer) {
        StringBuilder stringBuilder = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b == 0x00) {
                break;
            }
            stringBuilder.append((char) b);
        }
        return stringBuilder.toString();
    }

    private RequestImpl createHttpRequest(ByteBuffer buffer) throws Throwable {
        HttpSession httpSession = Mockito.mock(HttpSession.class);
        HttpServletRequest httpRequest = Mockito.mock(HttpServletRequest.class);
        RequestImpl requestImpl = spy(new RequestImpl(replacer.stapler, httpRequest, Collections.emptyList(), null));
        when(httpRequest.getSession(anyBoolean())).thenReturn(httpSession);
        int numParams = (int) buffer.get();
        if (numParams > 0) {
            for (int i = 0; i < numParams; ++i) {
                String name = readStringUntilNullByte(buffer);
                String value = readStringUntilNullByte(buffer);
                when(httpRequest.getParameter(name)).thenReturn(value);
            }
        }
        String form = readStringUntilNullByte(buffer);
        if (form.length() == 0) {
            form = "{}";
        }
        JSONObject formObject = JSONObject.fromObject(form);
        doReturn(formObject).when(requestImpl).getSubmittedForm();
        return requestImpl;
    }

    private void setPermission(int permission) {
        switch (permission) {
            case 0:
                enablePermission(PluginImpl.UPDATE_PERMISSION);
                break;
            case 1:
                enablePermission(PluginImpl.VIEW_PERMISSION);
                break;
            case 2:
                disablePermission(PluginImpl.UPDATE_PERMISSION);
                break;
            case 3:
                disablePermission(PluginImpl.VIEW_PERMISSION);
                break;
            default:
                break;
        }

    }

    private void enablePermission(Permission permission) {
        doNothing().when(jenkins).checkPermission(permission);
        when(jenkins.hasPermission(permission)).thenReturn(true);
    }

    private void disablePermission(Permission permission) {
        doCallRealMethod().when(jenkins).checkPermission(permission);
        when(jenkins.hasPermission(permission)).thenReturn(false);
    }
}
