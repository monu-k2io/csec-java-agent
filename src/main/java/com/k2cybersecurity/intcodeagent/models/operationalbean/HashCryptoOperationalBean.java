package com.k2cybersecurity.intcodeagent.models.operationalbean;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class HashCryptoOperationalBean extends AbstractOperationalBean {

	private String name;
	private String provider;  

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the provider
	 */
	public String getProvider() {
		return provider;
	}

	/**
	 * @param provider the provider to set
	 */
	public void setProvider(String provider) {
		this.provider = provider;
	}

	public HashCryptoOperationalBean(String name, String className, String sourceMethod, String executionId, long startTime) {
		super(className, sourceMethod, executionId, startTime);
		this.name = name;
	}

	public HashCryptoOperationalBean(HashCryptoOperationalBean cryptoOperationalBean) {
		super(cryptoOperationalBean);
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	@Override public boolean isEmpty() {
		return StringUtils.isBlank(name);
	}

}
