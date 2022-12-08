package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;

public class JSInjectionOperation extends AbstractOperation {

    private String javaScriptCode;

    public JSInjectionOperation(String javaScriptCode, String className, String methodName, String executionId,
                                long startTime) {
        super(className, methodName);
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
