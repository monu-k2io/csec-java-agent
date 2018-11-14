package org.brutusin.instrumentation.logging;

import org.brutusin.com.fasterxml.jackson.core.JsonProcessingException;
import org.brutusin.com.fasterxml.jackson.databind.ObjectMapper;
import com.k2.org.json.simple.JSONArray;


public class IntCodeResultBean extends AgentBasicInfo {

	private Integer pid;
	private String applicationUUID;
	private Long startTime;
	private String source;
	private String userClassName;
	private String userMethodName;
	private String currentMethod;
	private Integer lineNumber;
	private JSONArray parameters;
	private Long eventGenerationTime;

	public IntCodeResultBean() {
	}

	public IntCodeResultBean(Long startTime, String source, Integer pid, String applicationUUID) {
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.source = source;
		this.startTime = startTime;
	}
	
	public IntCodeResultBean(Long startTime, String source, JSONArray parameters, Integer pid, String applicationUUID) {
		this.setPid(pid);
		this.applicationUUID = applicationUUID;
		this.source = source;
		this.parameters = parameters;
		this.startTime = startTime;
	}

	public void setUserAPIInfo(Integer lineNumber, String userClassName, String userMethodName) {
		this.userMethodName = userMethodName;
		this.userClassName = userClassName;
		this.lineNumber = lineNumber;
	}

	public Long getStartTime() {
		return startTime;
	}

	public void setStartTime(Long startTime) {
		this.startTime = startTime;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public String getUserClassName() {
		return userClassName;
	}

	public void setUserClassName(String userClassName) {
		this.userClassName = userClassName;
	}

	public String getUserMethodName() {
		return userMethodName;
	}

	public void setUserMethodName(String userMethodName) {
		this.userMethodName = userMethodName;
	}

	public Integer getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(Integer lineNumber) {
		this.lineNumber = lineNumber;
	}

	public JSONArray getParameters() {
		return parameters;
	}

	public void setParameters(JSONArray parameters) {
		this.parameters = parameters;
	}

	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (JsonProcessingException e) {
			return null;
		}
	}

	/**
	 * @return the pid
	 */
	public Integer getPid() {
		return pid;
	}

	/**
	 * @param pid the pid to set
	 */
	public void setPid(Integer pid) {
		this.pid = pid;
	}

	/**
	 * @return the currentMethod
	 */
	public String getCurrentMethod() {
		return currentMethod;
	}

	/**
	 * @param currentMethod the currentMethod to set
	 */
	public void setCurrentMethod(String currentMethod) {
		this.currentMethod = currentMethod;
	}

	/**
	 * @return the eventGenerationTime
	 */
	public Long getEventGenerationTime() {
		return eventGenerationTime;
	}

	/**
	 * @param eventGenerationTime the eventGenerationTime to set
	 */
	public void setEventGenerationTime(Long eventGenerationTime) {
		this.eventGenerationTime = eventGenerationTime;
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

	
}
