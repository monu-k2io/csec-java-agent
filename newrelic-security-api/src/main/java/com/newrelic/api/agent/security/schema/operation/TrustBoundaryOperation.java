package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

public class TrustBoundaryOperation extends AbstractOperation {

    private String key;
    private Object value;

    public TrustBoundaryOperation(String key, Object value, String className, String methodName) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.TRUSTBOUNDARY);
        this.key = key;
        this.value = value;
    }

    /**
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * @param key the key to set
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * @return the value
     */
    public Object getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public boolean isEmpty() {
        return (key == null || key.trim().isEmpty());
    }


}
