package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class CVEScanner {

	private String appName;

	private String appSha256;

	private String dir;

	private Boolean isEnv;

	/**
	 * @param appName
	 * @param appSha256
	 * @param dir
	 */
	public CVEScanner(String appName, String appSha256, String dir, Boolean isEnv) {
		super();
		this.appName = appName;
		this.appSha256 = appSha256;
		this.dir = dir;
		this.isEnv = isEnv;
	}

	public Boolean getEnv() {
		return isEnv;
	}

	public void setEnv(Boolean env) {
		isEnv = env;
	}

	/**
	 * @return the appName
	 */
	public String getAppName() {
		return appName;
	}

	/**
	 * @param appName the appName to set
	 */
	public void setAppName(String appName) {
		this.appName = appName;
	}

	/**
	 * @return the appSha256
	 */
	public String getAppSha256() {
		return appSha256;
	}

	/**
	 * @param appSha256 the appSha256 to set
	 */
	public void setAppSha256(String appSha256) {
		this.appSha256 = appSha256;
	}

	/**
	 * @return the dir
	 */
	public String getDir() {
		return dir;
	}

	/**
	 * @param dir the dir to set
	 */
	public void setDir(String dir) {
		this.dir = dir;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);

	}
}
