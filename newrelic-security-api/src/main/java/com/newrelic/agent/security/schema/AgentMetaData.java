package com.newrelic.agent.security.schema;

import com.newrelic.agent.security.schema.annotations.JsonIgnore;

import java.util.*;

public class AgentMetaData {

    private boolean triggerViaRCI;

    private boolean triggerViaDeserialisation;

    private boolean triggerViaXXE;

    private boolean isClientDetectedFromXFF;

    private List<String> rciMethodsCalls;

    @JsonIgnore
    private boolean apiBlocked = false;

    private Map<String, String> userDataTranslationMap;

    @JsonIgnore
    private StackTraceElement[] serviceTrace;

    @JsonIgnore
    private Set<String> ips;

    @JsonIgnore
    private boolean isK2FuzzRequest = false;

    public AgentMetaData() {
        this.rciMethodsCalls = new ArrayList<>();
        this.ips = new HashSet<>();
        this.userDataTranslationMap = new HashMap<>();
    }

    public AgentMetaData(AgentMetaData agentMetaData) {
        this.rciMethodsCalls = new ArrayList<>();
        this.rciMethodsCalls.addAll(agentMetaData.rciMethodsCalls);
        this.triggerViaDeserialisation = agentMetaData.triggerViaDeserialisation;
        this.triggerViaRCI = agentMetaData.triggerViaRCI;
        this.isClientDetectedFromXFF = agentMetaData.isClientDetectedFromXFF;
        this.isK2FuzzRequest = agentMetaData.isK2FuzzRequest;
        this.serviceTrace = agentMetaData.serviceTrace;
        this.ips = new HashSet<>(agentMetaData.ips);
        this.apiBlocked = agentMetaData.apiBlocked;
        this.userDataTranslationMap = new HashMap<>(agentMetaData.userDataTranslationMap);
    }

    public boolean isTriggerViaRCI() {
        return triggerViaRCI;
    }

    public void setTriggerViaRCI(boolean triggerViaRCI) {
        this.triggerViaRCI = triggerViaRCI;
    }

    public boolean isTriggerViaDeserialisation() {
        return triggerViaDeserialisation;
    }

    public void setTriggerViaDeserialisation(boolean triggerViaDeserialisation) {
        this.triggerViaDeserialisation = triggerViaDeserialisation;
    }

    public boolean isTriggerViaXXE() {
        return triggerViaXXE;
    }

    public void setTriggerViaXXE(boolean triggerViaXXE) {
        this.triggerViaXXE = triggerViaXXE;
    }

    public List<String> getRciMethodsCalls() {
        return rciMethodsCalls;
    }

    public void setRciMethodsCalls(List<String> rciMethodsCalls) {
        this.rciMethodsCalls = rciMethodsCalls;
    }

    public boolean isClientDetectedFromXFF() {
        return isClientDetectedFromXFF;
    }

    public void setClientDetectedFromXFF(boolean clientDetectedFromXFF) {
        isClientDetectedFromXFF = clientDetectedFromXFF;
    }

    @JsonIgnore
    public boolean isK2FuzzRequest() {
        return isK2FuzzRequest;
    }

    @JsonIgnore
    public void setK2FuzzRequest(boolean k2FuzzRequest) {
        isK2FuzzRequest = k2FuzzRequest;
    }

    public StackTraceElement[] getServiceTrace() {
        return serviceTrace;
    }

    public void setServiceTrace(StackTraceElement[] serviceTrace) {
        this.serviceTrace = serviceTrace;
    }

    public Set<String> getIps() {
        return ips;
    }

    public void setIps(Set<String> ips) {
        this.ips = ips;
    }

    public boolean isApiBlocked() {
        return apiBlocked;
    }

    public void setApiBlocked(boolean apiBlocked) {
        this.apiBlocked = apiBlocked;
    }

    public Map<String, String> getUserDataTranslationMap() {
        return userDataTranslationMap;
    }

    public void setUserDataTranslationMap(Map<String, String> userDataTranslationMap) {
        this.userDataTranslationMap = userDataTranslationMap;
    }
}
