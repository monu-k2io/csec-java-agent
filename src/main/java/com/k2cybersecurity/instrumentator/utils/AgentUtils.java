package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.EventResponse;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AgentUtils {

	public Set<Pair<String, ClassLoader>> getTransformedClasses() {
		return transformedClasses;
	}

	private Set<Pair<String, ClassLoader>> transformedClasses;

	private Map<String, EventResponse> eventResponseSet;

	private static AgentUtils instance;


	private AgentUtils(){
		transformedClasses = new HashSet<>();
		eventResponseSet = new ConcurrentHashMap<>();
	}

	public static AgentUtils getInstance() {
		if(instance == null) {
			instance = new AgentUtils();
		}
		return instance;
	}

	public void clearTransformedClassSet(){
		transformedClasses.clear();
	}

	public Map<String, EventResponse> getEventResponseSet() {
		return eventResponseSet;
	}

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

}
