package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.io.Serializable;

import org.json.simple.JSONArray;

import com.google.gson.JsonArray;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ShutDownEvent extends AgentBasicInfo implements Serializable {

	private static final long serialVersionUID = -2320594688008671870L;
	
	private String applicationUUID;
	
	private String status;
	
	private JSONArray resonForTermination;
	
	private Integer exitCode;

	public ShutDownEvent() {
		super();
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
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * @param status the status to set
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * @return the resonForTermination
	 */
	public JSONArray getResonForTermination() {
		return resonForTermination;
	}

	/**
	 * @param resonForTermination the resonForTermination to set
	 */
	public void setResonForTermination(JSONArray resonForTermination) {
		this.resonForTermination = resonForTermination;
	}

	/**
	 * @return the exitCode
	 */
	public Integer getExitCode() {
		return exitCode;
	}

	/**
	 * @param exitCode the exitCode to set
	 */
	public void setExitCode(Integer exitCode) {
		this.exitCode = exitCode;
	}
	
	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

}
