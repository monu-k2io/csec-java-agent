package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;

public class AgentDetail {

    private String k2Version;

    private String k2ICToolId;

    private String jsonVersion;

    private Integer customerId;

    private String nodeIp;

    private String nodeId;

    private String nodeName;

    public AgentDetail() {
    }

    /**
     * @return the k2Version
     */
    public String getK2Version() {
        return k2Version;
    }

    /**
     * @param k2Version the k2Version to set
     */
    public void setK2Version(String k2Version) {
        this.k2Version = k2Version;
    }

    /**
     * @return the k2ICToolId
     */
    public String getK2ICToolId() {
        return k2ICToolId;
    }

    /**
     * @param k2icToolId the k2ICToolId to set
     */
    public void setK2ICToolId(String k2icToolId) {
        k2ICToolId = k2icToolId;
    }

    /**
     * @return the customerId
     */
    public Integer getCustomerId() {
        return customerId;
    }

    /**
     * @param customerId the customerId to set
     */
    public void setCustomerId(Integer customerId) {
        this.customerId = customerId;
    }

    /**
     * @return the nodeIp
     */
    public String getNodeIp() {
        return nodeIp;
    }

    /**
     * @param nodeIp the nodeIp to set
     */
    public void setNodeIp(String nodeIp) {
        this.nodeIp = nodeIp;
    }

    /**
     * @return the nodeId
     */
    public String getNodeId() {
        return nodeId;
    }

    /**
     * @param nodeId the nodeId to set
     */
    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    /**
     * @return the nodeName
     */
    public String getNodeName() {
        return nodeName;
    }

    /**
     * @param nodeName the nodeName to set
     */
    public void setNodeName(String nodeName) {
        this.nodeName = nodeName;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    /**
     * @return the jsonVersion
     */
    public String getJsonVersion() {
        return jsonVersion;
    }

    /**
     * @param jsonVersion the jsonVersion to set
     */
    public void setJsonVersion(String jsonVersion) {
        this.jsonVersion = jsonVersion;
    }

}
