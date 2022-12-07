package com.newrelic.api.agent.security.schema;

import java.util.Arrays;

public abstract class AbstractOperation {

    public static final String EMPTY = "";
    private String className;

    private String methodName;

    private String sourceMethod;

    private String executionId;

    private long startTime;

    private long blockingEndTime;

    private StackTraceElement[] stackTrace;

    private UserClassEntity userClassEntity;

    private String apiID;

    public AbstractOperation() {
        this.className = EMPTY;
        this.sourceMethod = EMPTY;
        this.executionId = EMPTY;
        this.methodName = EMPTY;
        this.startTime = 0L;
        this.blockingEndTime = 0L;
        this.apiID = EMPTY;
    }

    public AbstractOperation(String className, String methodName, String executionId
            , long startTime){
        this.className = className;
        this.sourceMethod = sourceMethod;
        this.executionId = executionId;
        this.startTime = startTime;
        this.methodName = methodName;
        this.blockingEndTime = 0L;
    }

    public AbstractOperation(String className, String methodName, String executionId
            , long startTime, int currentGenericServletStackLength) {
        this(className, methodName, executionId, startTime);
        if (currentGenericServletStackLength >= 0) {
//            this.stackTrace = Arrays.copyOfRange(this.stackTrace, 0, this.stackTrace.length - currentGenericServletStackLength + 3);
        }
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getSourceMethod() {
        return sourceMethod;
    }

    public void setSourceMethod(String sourceMethod) {
        this.sourceMethod = sourceMethod;
    }

    public String getExecutionId() {
        return executionId;
    }

    public void setExecutionId(String executionId) {
        this.executionId = executionId;
    }

    public long getStartTime() {
        return startTime;
    }

    /**
     * Logically determines if the bean is empty.
     *
     * @return boolean
     */
    public abstract boolean isEmpty();

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getBlockingEndTime() {
        return blockingEndTime;
    }

    public void setBlockingEndTime(long blockingEndTime) {
        this.blockingEndTime = blockingEndTime;
    }

    public StackTraceElement[] getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stackTrace = stackTrace;
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public UserClassEntity getUserClassEntity() {
        return userClassEntity;
    }

    public void setUserClassEntity(UserClassEntity userClassEntity) {
        this.userClassEntity = userClassEntity;
    }

    public String getApiID() {
        return apiID;
    }

    public void setApiID(String apiID) {
        this.apiID = apiID;
    }
}
