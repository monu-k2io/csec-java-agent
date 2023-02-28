package com.newrelic.agent.security.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.IntCodeControlCommand;
import com.newrelic.agent.security.intcodeagent.websocket.WSUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * Request repeater for IAST
 */
public class RestRequestProcessor implements Runnable {

    public static final String K2_HOME_TMP_CONST = "{{K2_HOME_TMP}}";
    public static final String ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S = "Error while processing fuzzing request : %s";
    private static final int MAX_REPETITION = 3;
    private IntCodeControlCommand controlCommand;

    private int repeatCount;

    private ObjectMapper objectMapper = new ObjectMapper();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public RestRequestProcessor(IntCodeControlCommand controlCommand, int repeatCount) {
        this.controlCommand = controlCommand;
        this.repeatCount = repeatCount;
    }


    /**
     * Does the request replay in IAST mode.
     */
    @Override
    public void run() {
        if (controlCommand.getArguments().size() < 2) {
            return;
        }

        FuzzRequestBean httpRequest = null;
        try {
            if (WSUtils.getInstance().isReconnecting()) {
                synchronized (WSUtils.getInstance()) {
                    RestRequestThreadPool.getInstance().isWaiting().set(true);
                    WSUtils.getInstance().wait();
                    RestRequestThreadPool.getInstance().isWaiting().set(false);
                }
            }
            String req = StringUtils.replace(controlCommand.getArguments().get(0), K2_HOME_TMP_CONST, OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory());
            httpRequest = objectMapper.readValue(req, FuzzRequestBean.class);
            RestClient.getInstance().fireRequest(RequestUtils.generateK2Request(httpRequest), repeatCount);

        } catch (Throwable e) {
            logger.log(LogLevel.ERROR,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
            logger.postLogMessageIfNecessary(LogLevel.ERROR,
                    String.format(ERROR_WHILE_PROCESSING_FUZZING_REQUEST_S, controlCommand.getArguments().get(0)),
                    e, RestRequestProcessor.class.getName());
        }
    }

    public static void processControlCommand(IntCodeControlCommand command) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command, MAX_REPETITION));
    }

    public static void processControlCommand(IntCodeControlCommand command, int repeat) {
        RestRequestThreadPool.getInstance().executor
                .submit(new RestRequestProcessor(command, repeat));
    }
}
