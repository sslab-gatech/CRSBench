package com.aixcc.pac4j.harnesses.one;

import org.pac4j.core.profile.InternalAttributeHandler;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

public class Pac4jOne {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            final InternalAttributeHandler handler = new InternalAttributeHandler();
            handler.restore(new String(data));
        } catch (FuzzerSecurityIssueLow | FuzzerSecurityIssueMedium | FuzzerSecurityIssueHigh | FuzzerSecurityIssueCritical e) {
            throw e;
        } catch (Exception e) {
        }
    }
}
