package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class JSInjectionOperation extends AbstractOperation {

    private String javaScriptCode;

    public JSInjectionOperation(String javaScriptCode, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.JAVASCRIPT_INJECTION);
        this.javaScriptCode = javaScriptCode;
    }

    public String getJavaScriptCode() {
        return javaScriptCode;
    }

    public void setJavaScriptCode(String javaScriptCode) {
        this.javaScriptCode = javaScriptCode;
    }

    @Override
    public boolean isEmpty() {
        return (javaScriptCode == null || javaScriptCode.trim().isEmpty());
    }

    @Override
    public String toString() {
        return "expression : " + javaScriptCode;
    }

}
