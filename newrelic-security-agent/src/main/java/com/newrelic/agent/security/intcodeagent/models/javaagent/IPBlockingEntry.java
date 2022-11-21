package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

import java.util.Objects;

public class IPBlockingEntry {

    private long creationTimestamp;

    private String targetIP;

    public IPBlockingEntry(String targetIP) {
        this.targetIP = targetIP;
        this.creationTimestamp = System.currentTimeMillis();
    }

    public long getCreationTimestamp() {
        return creationTimestamp;
    }

    public void setCreationTimestamp(long creationTimestamp) {
        this.creationTimestamp = creationTimestamp;
    }

    public String getTargetIP() {
        return targetIP;
    }

    public void setTargetIP(String targetIP) {
        this.targetIP = targetIP;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);

    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IPBlockingEntry that = (IPBlockingEntry) o;
        return creationTimestamp == that.creationTimestamp &&
                targetIP.equals(that.targetIP);
    }

    @Override
    public int hashCode() {
        return Objects.hash(creationTimestamp, targetIP);
    }

}
