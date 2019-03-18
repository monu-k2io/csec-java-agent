package org.brutusin.instrumentation.logging;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public class ServletEventProcessor implements Runnable {

	private Object firstElement;
	private ServletInfo servletInfo;
	private String sourceString; 
	private Long threadId;
	
	/**
	 * @return the firstElement
	 */
	public Object getFirstElement() {
		return firstElement;
	}

	/**
	 * @param firstElement the firstElement to set
	 */
	public void setFirstElement(Object firstElement) {
		this.firstElement = firstElement;
	}

	/**
	 * @return the servletInfo
	 */
	public ServletInfo getServletInfo() {
		return servletInfo;
	}

	/**
	 * @param servletInfo the servletInfo to set
	 */
	public void setServletInfo(ServletInfo servletInfo) {
		this.servletInfo = servletInfo;
	}

	/**
	 * @return the sourceString
	 */
	public String getSourceString() {
		return sourceString;
	}

	/**
	 * @param sourceString the sourceString to set
	 */
	public void setSourceString(String sourceString) {
		this.sourceString = sourceString;
	}

	/**
	 * @return the threadId
	 */
	public Long getThreadId() {
		return threadId;
	}

	/**
	 * @param threadId the threadId to set
	 */
	public void setThreadId(Long threadId) {
		this.threadId = threadId;
	}

	public ServletEventProcessor(Object firstElement, ServletInfo servletInfo, String sourceString, long threadId) {
		this.firstElement = firstElement;
		this.servletInfo = servletInfo;
		this.sourceString = sourceString;
		this.threadId = threadId;
	}

	@Override
	public void run() {
		try {
			if (IAgentConstants.TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)) {
				ByteBuffer bb = null;
				
				Field inputBufferField = firstElement.getClass().getDeclaredField("inputBuffer");
				inputBufferField.setAccessible(true);
				Object inputBuffer = inputBufferField.get(firstElement);

				Field bytes = inputBuffer.getClass().getDeclaredField("byteBuffer");
				bytes.setAccessible(true);
				bb = (ByteBuffer) bytes.get(inputBuffer);

				servletInfo.setRawParameters(readByteBuffer(bb));
				System.out.println(servletInfo.getRawParameters());
				
			} else if (IAgentConstants.HTTP_SERVLET_SERVICE.equals(sourceString)) {
				Method getQueryString = firstElement.getClass().getMethod("getQueryString");
				Method getRemoteAddr = firstElement.getClass().getMethod("getRemoteAddr");
				Method getMethod = firstElement.getClass().getMethod("getMethod");
				Method getContentType = firstElement.getClass().getMethod("getContentType");

				servletInfo.setQueryString((String) getQueryString.invoke(firstElement, null));
				servletInfo.setSourceIp((String) getRemoteAddr.invoke(firstElement, null));
				servletInfo.setRequestMethod((String) getMethod.invoke(firstElement, null));
				servletInfo.setContentType((String) getContentType.invoke(firstElement, null));
			}
		} catch (Exception e) {
			e.printStackTrace();
			LoggingInterceptor.requestMap.remove(threadId);
		}
	}
	
	private static String readByteBuffer(ByteBuffer buffer) {
		int currPos = buffer.position();
		StringBuffer stringBuffer = new StringBuffer();
		while (buffer.remaining() > 0) {
			stringBuffer.append((char) buffer.get());
		}
		buffer.position(currPos);
		return stringBuffer.toString();
	}

}
