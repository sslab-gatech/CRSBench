package com.aixcc.jenkins.harnesses.five;

import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletContext;

import javax.naming.NamingException;

import aixcc.util.StaplerReplacer;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;

import hudson.plugins.emailext.EmailStageList;
import hudson.plugins.emailext.EmailConfig;
import hudson.plugins.emailext.EmailStateRun;
import jenkins.model.Jenkins;

import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.*;
import org.mockito.Mockito;

public class JenkinsFive {
    static Jenkins jenkins;
    static StaplerReplacer replacer;
    static ResponseImpl rsp;

    public static void fuzzerInitialize() throws Throwable {
        jenkins = Mockito.mock(Jenkins.class);
        
        replacer = new StaplerReplacer();
        replacer.setWebApp(new WebApp(Mockito.mock(ServletContext.class)));

        rsp = Mockito.mock(ResponseImpl.class);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        when(rsp.getWriter()).thenReturn(pw);
    }

    public static void fuzzerTestOneInput(byte[] data) throws Throwable {
        try {
            new JenkinsFive().fuzz(data);
        } catch (FuzzerSecurityIssueLow | FuzzerSecurityIssueMedium | FuzzerSecurityIssueHigh
                | FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {
        }
    }

    public void fuzz(byte[] data) throws Throwable {
        EmailConfig emailConfig = new EmailConfig();
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int numRequests = Byte.toUnsignedInt(buffer.get());
        if (numRequests < 0)
            return;
        
        for (int i = 0; i < numRequests; ++i) {
            int command = Byte.toUnsignedInt(buffer.get());
            switch(command){
                case 1:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.constructor();
                    break;
                case 2:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.okForPublish();
                    break;
                case 3:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.setEmailAddress();
                    break;
                case 4:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.okForPublish();
                    break;
                case 5:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.wrapUp();
                    break;
                case 6:
                    emailConfig.optCache = readByteAsString(buffer);
                    emailConfig.destructor();
                    break;
                case 11:
                    List<EmailStageList> list = makeEmailStageList(buffer);
                    testEmailStageRun(list);
                    break;
                default:
                    break;
            }
        }
        
    }

    private String readByteAsString(ByteBuffer buffer) {
        if (buffer.remaining() < 1) {
            return "";
        }
        int length = Byte.toUnsignedInt(buffer.get());
        if (length == 0 || buffer.remaining() < length) {
            return "";
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public List<EmailStageList> makeEmailStageList(ByteBuffer buffer){
        List<EmailStageList> list = new ArrayList<>();
        if (buffer.remaining() < 1) {
            return list;
        }
        int count = Byte.toUnsignedInt(buffer.get());

        for (int i = 0; i < count; i++) {
            if (buffer.remaining() < 1) {
                break;
            }
            int dataLen = Byte.toUnsignedInt(buffer.get());
            if (dataLen > buffer.remaining()) {
                break;
            }
            byte[] dataBytes = new byte[dataLen];
            buffer.get(dataBytes);
            String parsedData = new String(dataBytes, StandardCharsets.UTF_8);
            if (buffer.remaining() < 1) {
                break;
            }
            int stageJumpLen = Byte.toUnsignedInt(buffer.get());
            if (stageJumpLen > buffer.remaining()) {
                break;
            }
            byte[] stageJumpBytes = new byte[stageJumpLen];
            buffer.get(stageJumpBytes);
            String parsedStageJump = new String(stageJumpBytes, StandardCharsets.UTF_8);
    
            EmailStageList esl = new EmailStageList();
            esl.data = parsedData;
            esl.stageJump = parsedStageJump;
            list.add(esl);
        }
        return list;
    }

    private void testEmailStageRun(List<EmailStageList> list) {
        EmailStateRun emailStateRun = new EmailStateRun();
        String result = emailStateRun.run(list);
    }
}
