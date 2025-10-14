package com.aixcc.jenkins.harnesses.five;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.http.HttpResponse;
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

public class JenkinsFiveFDP {
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

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Throwable {
        try {
            new JenkinsFiveFDP().fuzz(data);
        } catch (FuzzerSecurityIssueLow | FuzzerSecurityIssueMedium | FuzzerSecurityIssueHigh
                | FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Throwable t) {
        }
    }

    public void fuzz(FuzzedDataProvider data) throws Throwable {
        EmailConfig emailConfig = new EmailConfig();
        int numRequests = Byte.toUnsignedInt(data.consumeByte());
        if (numRequests < 0)
            return;
        
        for (int i = 0; i < numRequests; ++i) {
            int command = Byte.toUnsignedInt(data.consumeByte());
            switch(command){
                case 1:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.constructor();
                    break;
                case 2:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.okForPublish();
                    break;
                case 3:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.setEmailAddress();
                    break;
                case 4:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.okForPublish();
                    break;
                case 5:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.wrapUp();
                    break;
                case 6:
                    emailConfig.optCache = readByteAsString(data);
                    emailConfig.destructor();
                    break;
                case 11:
                    List<EmailStageList> list = makeEmailStageList(data);
                    testEmailStageRun(list);
                    break;
                default:
                    break;
            }
        }
        
    }

    private String readByteAsString(FuzzedDataProvider data) {
        if (data.remainingBytes() < 1) {
            return "";
        }
        int length = Byte.toUnsignedInt(data.consumeByte());
        if (length == 0 || data.remainingBytes() < length) {
            return "";
        }
        return data.consumeString(length);
    }

    public List<EmailStageList> makeEmailStageList(FuzzedDataProvider data){
        List<EmailStageList> list = new ArrayList<>();
        if (data.remainingBytes() < 1) {
            return list;
        }
        int count = Byte.toUnsignedInt(data.consumeByte());

        for (int i = 0; i < count; i++) {
            if (data.remainingBytes() < 1) {
                break;
            }
            int dataLen = Byte.toUnsignedInt(data.consumeByte());
            if (dataLen > data.remainingBytes()) {
                break;
            }
            String parsedData = data.consumeString(dataLen);
            if (data.remainingBytes() < 1) {
                break;
            }
            int stageJumpLen = Byte.toUnsignedInt(data.consumeByte());
            if (stageJumpLen > data.remainingBytes()) {
                break;
            }
            String parsedStageJump = data.consumeString(stageJumpLen);
    
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
