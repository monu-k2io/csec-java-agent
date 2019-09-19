package com.k2cybersecurity.intcodeagent.models.javaagent;

import java.util.Arrays;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class HttpRequestBean {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String GOT_EMPTY_COMPONENT_LIST_FROM_RAW_REQUEST = "Got empty component list from raw request.";
	public static final String UNABLE_TO_EXTRACT_THE_REQUEST_LINE = "Unable to extract the request line.";
	public static final String GOT_EMPTY_MAP_AFTER_EXTRACTING_THE_HEADERS = "Got empty map after extracting the headers.";
	public static final String GOT_EMPTY_BODY_AFTER_PROCESSING = "Got empty body after processing";
	public static final String DOUBLE_NL_SEPARATOR = "\n\n";
	public static final String DOUBLE_CR_SEPARATOR = "\r\n\r\n";
	public static final String ERROR_WHILE_PROCESSING_HEADERS = "Error while processing headers : ";
	public static final String COLON_SEPARATOR_CHAR = ":";
	public static final String ERROR_WHILE_PROCESSING_REQUEST_LINE = "Error while processing request line : ";
	public static final String INVALID_REQUEST_LINE_MISSING_MANDATORY_COMPONENTS = "Invalid request line. Missing mandatory components : ";
	public static final String CR_OR_NL_SEPARATOR = "\n";

	private String body;

	private String rawRequest;

	private Integer generationTime;

	private boolean dataTruncated;

	private String method;

	private String url;

	private JSONObject headers;

	public HttpRequestBean() {
		this.rawRequest = StringUtils.EMPTY;
		this.generationTime = 0;
		this.body = StringUtils.EMPTY;
		this.dataTruncated = false;
		this.method = StringUtils.EMPTY;
		this.url = StringUtils.EMPTY;
		this.headers = new JSONObject();
	}

	public HttpRequestBean(HttpRequestBean servletInfo) {
		this.rawRequest = servletInfo.getRawRequest();
		this.generationTime = servletInfo.getGenerationTime();
		this.body = servletInfo.getBody();
		this.dataTruncated = servletInfo.isDataTruncated();
		this.method = servletInfo.getMethod();
		this.url = servletInfo.getUrl();
		this.headers = new JSONObject(servletInfo.getHeaders());
		populateHttpRequest();
	}

	public String getRawRequest() {
		return rawRequest;
	}

	public void setRawRequest(String rawRequest) {
		this.rawRequest = rawRequest;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public JSONObject getHeaders() {
		return headers;
	}

	public void setHeaders(JSONObject headers) {
		this.headers = headers;
	}

	/**
	 * @return the body
	 */
	public String getBody() {
		return this.body;
	}

	/**
	 * @param body the body to set
	 */
	public void setBody(String body) {
		this.body = body;
	}

	/**
	 * @return the dataTruncated
	 */
	public boolean isDataTruncated() {
		return this.dataTruncated;
	}

	/**
	 * @param dataTruncated the dataTruncated to set
	 */
	public void setDataTruncated(boolean dataTruncated) {
		this.dataTruncated = dataTruncated;
	}

	/**
	 * @return the generationTime
	 */
	public Integer getGenerationTime() {
		return generationTime;
	}

	/**
	 * @param generationTime the generationTime to set
	 */
	public void setGenerationTime(Integer generationTime) {
		this.generationTime = generationTime;
	}

	public Integer addGenerationTime(Integer time) {
		this.generationTime += time;
		return this.generationTime;
	}

	public String[] splitRequestComponents() {
		return StringUtils.splitPreserveAllTokens(this.rawRequest, CR_OR_NL_SEPARATOR);
	}

	public boolean parseRequestLineFromRawRequest(String[] components) {
		try {
			String requestLine = components[0];
			String[] requestLineComponents = StringUtils.split(requestLine);
			if (requestLineComponents.length >= 1) {
				this.method = requestLineComponents[0];
				this.url = requestLineComponents[1];
			} else {
				logger.log(LogLevel.ERROR,
						INVALID_REQUEST_LINE_MISSING_MANDATORY_COMPONENTS + Arrays.asList(requestLineComponents), this.getClass().getName());
				return false;
			}
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_WHILE_PROCESSING_REQUEST_LINE + this.rawRequest, this.getClass().getName());
			return false;
		}
		return true;
	}

	public boolean parseHeadersFromRawRequest(String[] components) {
		this.headers = new JSONObject();
		int resetCounter = 0;
		try {
			for (int i = 1; i < components.length; i++) {
				String currentLine = components[i];
//				System.out.println("Current line : " + currentLine);
				if (StringUtils.isEmpty(currentLine)){
					resetCounter ++;
					if (resetCounter == 4) {
						break;
					}
				} else {
					resetCounter = 0;
				}
				String[] currentComponents = new String[] {StringUtils.substringBefore(currentLine, COLON_SEPARATOR_CHAR),StringUtils.substringAfter(currentLine, COLON_SEPARATOR_CHAR)};
				if (currentComponents.length > 1 && StringUtils.isNoneBlank(currentComponents)) {
					this.headers.put(currentComponents[0].trim(), currentComponents[1].trim());
				}
			}
			return this.headers.size() > 0;
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR_WHILE_PROCESSING_HEADERS + this.rawRequest, this.getClass().getName());
			return false;
		}
	}

	public boolean parseBodyFromRawRequest() {
		this.body = StringUtils.substringAfter(this.rawRequest, DOUBLE_CR_SEPARATOR);
		if (StringUtils.isEmpty(this.body)){
			this.body = StringUtils.substringAfter(this.rawRequest, DOUBLE_NL_SEPARATOR);
		}
		return this.body.length() > 0;
	}

	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	public void populateHttpRequest() {
		this.setRawRequest(StringEscapeUtils.unescapeJava(this.getRawRequest()));
		String[] components = splitRequestComponents();
		if (components == null || components.length == 0) {
			logger.log(LogLevel.ERROR, GOT_EMPTY_COMPONENT_LIST_FROM_RAW_REQUEST, this.getClass().getName());
			return;
		}
		System.out.println(Arrays.asList(components));
		if (!parseRequestLineFromRawRequest(components)) {
			logger.log(LogLevel.ERROR, UNABLE_TO_EXTRACT_THE_REQUEST_LINE, this.getClass().getName());
			return;
		}

		if (!parseHeadersFromRawRequest(components)) {
			logger.log(LogLevel.ERROR, GOT_EMPTY_MAP_AFTER_EXTRACTING_THE_HEADERS, this.getClass().getName());
			return;
		}

		if (!parseBodyFromRawRequest()) {
			logger.log(LogLevel.WARNING, GOT_EMPTY_BODY_AFTER_PROCESSING, this.getClass().getName());
		}

		this.rawRequest = StringUtils.EMPTY;
	}
}
