package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class JAHealthCheck extends AgentBasicInfo {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	private static final String HC_CREATED = "Created Health Check: %s";

    private String applicationUUID;

//    private String protectedServer;

//    private Set protectedDB;

    private AtomicInteger eventDropCount;

    private IdentifierEnvs kind;

    private AtomicInteger eventProcessed;

    private AtomicInteger eventSentCount;

    private AtomicInteger exitEventSentCount;

    private AtomicInteger httpRequestCount;

    private Map<String, Object> stats;

    private Map<String, Object> serviceStatus;

//    private Set protectedVulnerabilities;

    private Integer dsBackLog;

    public JAHealthCheck(String applicationUUID) {
        super();
        this.applicationUUID = applicationUUID;
        this.eventDropCount = new AtomicInteger(0);
        this.eventProcessed = new AtomicInteger(0);
        this.eventSentCount = new AtomicInteger(0);
        this.httpRequestCount = new AtomicInteger(0);
        this.exitEventSentCount = new AtomicInteger(0);
        this.stats = new HashMap<>();
        this.serviceStatus = new HashMap<>();
        this.setKind(AgentInfo.getInstance().getApplicationInfo().getIdentifier().getKind());
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public JAHealthCheck(JAHealthCheck jaHealthCheck) {
        super();
        this.applicationUUID = jaHealthCheck.applicationUUID;
        this.eventDropCount = jaHealthCheck.eventDropCount;
        this.eventProcessed = jaHealthCheck.eventProcessed;
        this.eventSentCount = jaHealthCheck.eventSentCount;
        this.exitEventSentCount = jaHealthCheck.exitEventSentCount;
        this.httpRequestCount = jaHealthCheck.httpRequestCount;
        this.kind = jaHealthCheck.kind;
        this.stats = jaHealthCheck.stats;
        this.serviceStatus = jaHealthCheck.serviceStatus;
        this.dsBackLog = jaHealthCheck.dsBackLog;
        logger.log(LogLevel.INFO, String.format(HC_CREATED, JsonConverter.toJSON(this)), JAHealthCheck.class.getName());
    }

    public IdentifierEnvs getKind() {
        return kind;
    }

    public void setKind(IdentifierEnvs kind) {
        this.kind = kind;
    }

    /**
     * @return the applicationUUID
     */
    public String getApplicationUUID() {
        return applicationUUID;
    }

    /**
     * @param applicationUUID the applicationUUID to set
     */
    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }

    /**
     * @return the eventDropCount
     */
    public Integer getEventDropCount() {
        return eventDropCount.get();
    }

    /**
     * @param eventDropCount the eventDropCount to set
     */
    public void setEventDropCount(Integer eventDropCount) {
        this.eventDropCount.set(eventDropCount);
    }

    public void incrementDropCount() {
        this.eventDropCount.getAndIncrement();
    }

    public void incrementProcessedCount() {
        this.eventProcessed.getAndIncrement();
    }

    public void incrementEventSentCount() {
        this.eventSentCount.getAndIncrement();
    }

    public void decrementEventSentCount() {
        this.eventSentCount.getAndDecrement();
    }

    public AtomicInteger getExitEventSentCount() {
        return exitEventSentCount;
    }

    public AtomicInteger getHttpRequestCount() {
        return httpRequestCount;
    }

    public void incrementHttpRequestCount() {
        this.httpRequestCount.getAndIncrement();
    }

    public void decrementHttpRequestCount() {
        this.httpRequestCount.getAndDecrement();
    }

    public void incrementExitEventSentCount() {
        this.exitEventSentCount.getAndIncrement();
    }

    public void decrementExitEventSentCount() {
        this.exitEventSentCount.getAndDecrement();
    }

    public void setExitEventSentCount(Integer exitEventSentCount) {
        this.exitEventSentCount.set(exitEventSentCount);
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    /**
     * @return the eventProcessed
     */
    public Integer getEventProcessed() {
        return eventProcessed.get();
    }

    /**
     * @param eventProcessed the eventProcessed to set
     */
    public void setEventProcessed(Integer eventProcessed) {
        this.eventProcessed.set(eventProcessed);
    }

    /**
     * @return the eventSentCount
     */
    public AtomicInteger getEventSentCount() {
        return eventSentCount;
    }

    /**
     * @param eventSentCount the eventSentCount to set
     */
    public void setEventSentCount(Integer eventSentCount) {
        this.eventSentCount.set(eventSentCount);
    }

    public void setHttpRequestCount(Integer httpRequestCount) {
        this.httpRequestCount.set(httpRequestCount);
    }

    public Integer getDsBackLog() {
        return dsBackLog;
    }

    public void setDsBackLog(Integer dsBackLog) {
        this.dsBackLog = dsBackLog;
    }

    public Map<String, Object> getStats() {
        return stats;
    }

    public void setStats(Map<String, Object> stats) {
        this.stats = stats;
    }

    public Map<String, Object> getServiceStatus() {
        return serviceStatus;
    }

    public void setServiceStatus(Map<String, Object> serviceStatus) {
        this.serviceStatus = serviceStatus;
    }
}
