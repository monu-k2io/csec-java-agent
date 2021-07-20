package com.k2cybersecurity.intcodeagent.models.operationalbean;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

public class SystemExitOperationalBean extends AbstractOperationalBean {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private String exitCode;

    public SystemExitOperationalBean(String cmd, String className, String sourceMethod, String executionId,
                                     long startTime, String methodName) {
        super(className, sourceMethod, executionId, startTime, methodName);
        this.exitCode = cmd;

    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    @Override
    public boolean isEmpty() {
        return StringUtils.isBlank(exitCode);
    }

    public String getExitCode() {
        return exitCode;
    }

    public void setExitCode(String exitCode) {
        this.exitCode = exitCode;
    }
}
