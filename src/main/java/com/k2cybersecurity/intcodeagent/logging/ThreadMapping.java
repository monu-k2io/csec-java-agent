package com.k2cybersecurity.intcodeagent.logging;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.apache.commons.lang3.tuple.Pair;

public class ThreadMapping {

	private static ThreadMapping threadMapping;
	
	private Map<Pair<Long, Long>, ConcurrentLinkedDeque<ThreadRequestData>> tempThreadRequestMap = new ConcurrentHashMap<>();

	private Map<Long, ConcurrentLinkedDeque<ThreadRequestData>> mappedThreadRequestMap = new ConcurrentHashMap<>();

	/**
	 * @return the tempThreadRequestMap
	 */
	public Map<Pair<Long, Long>, ConcurrentLinkedDeque<ThreadRequestData>> getTempThreadRequestMap() {
		return tempThreadRequestMap;
	}

	/**
	 * @return the mappedThreadRequestMap
	 */
	public Map<Long, ConcurrentLinkedDeque<ThreadRequestData>> getMappedThreadRequestMap() {
		return mappedThreadRequestMap;
	}
	
	public static ThreadMapping getInstance() {
		if(threadMapping == null)
			threadMapping = new ThreadMapping();
		return threadMapping;
	}

}
