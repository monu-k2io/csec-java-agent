package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

public class HashCryptoOperation extends AbstractOperation {

    private String name;
    private String provider;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the provider
     */
    public String getProvider() {
        return provider;
    }

    /**
     * @param provider the provider to set
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }

    public HashCryptoOperation(String name, String className, String methodName, String executionId, long startTime) {
        super(className, methodName, executionId, startTime);
        this.name = name;
    }

    @Override
    public boolean isEmpty() {
        return (name == null || name.trim().isEmpty());
    }

}
