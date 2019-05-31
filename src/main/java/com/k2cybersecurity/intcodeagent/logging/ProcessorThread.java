package com.k2cybersecurity.intcodeagent.logging;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_LOADER_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HSQL_V2_4;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MOGNO_ELEMENT_DATA_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COLLECTION_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COLLECTION_WILDCARD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_NAME_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DELETE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DELETE_REQUEST_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DISTINCT_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DOCUMENT_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIELD_NAME_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FILTER_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIND_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_INSERT_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_INSERT_REQUESTS_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_MULTIPLE_UPDATES_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_NAMESPACE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_PAYLOAD_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_SINGLE_UPDATE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_UPDATE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_WRITE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_WRITE_REQUEST_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_ACTIVE_CONNECTION_PROP_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_PARAM_VALUES_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_BUFFER_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_CONNECTION_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_CURRENT_OBJECT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IMPL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_INPUT_DTV_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IN_OUT_PARAM_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_PREPARED_BATCH_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_PREPARED_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_SERVER_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_SQL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_STATEMENT_EXECUTE_CMD_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_STATEMENT_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_USER_SQL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_VALUE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_CONNECTION_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_DB_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_STATEMENT_CLASS_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQL42_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV2_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV3_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV3_EXECUTOR7_4;

import java.lang.reflect.Field;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Pattern;

//import org.brutusin.commons.json.spi.JsonCodec;
import org.brutusin.instrumentation.Agent;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentDynamicPathBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.ServletInfo;

public class ProcessorThread implements Runnable {

	private static final Map<String, List<String>> interceptMethod;
	private static final Pattern PATTERN;
	private static final Set<String> executorMethods;
	private static final Set<String> mongoExecutorMethods;

	
	private Object source;
	private Object[] arg;
	private Integer executionId;
	private StackTraceElement[] stackTrace;
	private Long threadId;
	private String sourceString;
	private ObjectMapper mapper;
	private JSONParser parser;

	private LinkedBlockingQueue<Object> eventQueue;
	private Socket currentSocket;
	static {
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		executorMethods = new HashSet<>(Arrays.asList(IAgentConstants.EXECUTORS));
		executorMethods.addAll(Arrays.asList(IAgentConstants.MONGO_EXECUTORS));
		mongoExecutorMethods = new HashSet<>(Arrays.asList(IAgentConstants.MONGO_EXECUTORS));
		interceptMethod = new HashMap<>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i],
					new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
		}
		}

	/**
	 * @param source
	 * @param arg
	 * @param executionId
	 * @param stackTrace
	 * @param tId
	 * @param servletInfo
	 */

	public ProcessorThread(Object source, Object[] arg, Integer executionId, StackTraceElement[] stackTrace, long tId,
			String sourceString) {
		this.source = source;
		this.arg = arg;
		this.executionId = executionId;
		this.stackTrace = stackTrace;
		this.threadId = tId;
		this.sourceString = sourceString;
		this.mapper = new ObjectMapper();
		this.parser = new JSONParser();
		this.eventQueue = EventThreadPool.getInstance().getEventQueue();
		this.currentSocket = EventThreadPool.getInstance().getSocket();
		
	}

	/**
	 * @return the source
	 */
	public Object getSource() {
		return source;
	}

	/**
	 * @param source the source to set
	 */
	public void setSource(Object source) {
		this.source = source;
	}

	/**
	 * @return the arg
	 */
	public Object[] getArg() {
		return arg;
	}

	/**
	 * @param arg the arg to set
	 */
	public void setArg(Object[] arg) {
		this.arg = arg;
	}

	/**
	 * @return the executionId
	 */
	public Integer getExecutionId() {
		return executionId;
	}

	/**
	 * @param executionId the executionId to set
	 */
	public void setExecutionId(Integer executionId) {
		this.executionId = executionId;
	}

	@Override
	public void run() {
		try {
			if (executorMethods.contains(sourceString)) {

				long start = System.currentTimeMillis();

				JavaAgentEventBean intCodeResultBean = new JavaAgentEventBean(start, sourceString,
						LoggingInterceptor.VMPID, LoggingInterceptor.applicationUUID,
						this.threadId + IAgentConstants.COLON_SEPERATOR + this.executionId);

				// System.out.println("Inside processor servlet info found: threadId:
				// "+this.threadId +". "+ intCodeResultBean.getServletInfo());
				String klassName = null;
				if (mongoExecutorMethods.contains(sourceString)) {
					intCodeResultBean.setValidationBypass(true);
				}

				// String methodName = null;
				StackTraceElement[] trace = this.stackTrace;
				if (IAgentConstants.FILE_OPEN_EXECUTORS.contains(sourceString)) {

					// System.out.println("file operation found");
					boolean javaIoFile = false;
					for (int i = 0; i < trace.length; i++) {
						klassName = trace[i].getClassName();
						if (javaIoFile) {
							if (!PATTERN.matcher(klassName).matches()) {
								intCodeResultBean.setParameters(toString(arg, sourceString));
								intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName,
										trace[i].getMethodName());
								if (i > 0)
									intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
							}
							if (intCodeResultBean.getUserClassName() != null
									&& !intCodeResultBean.getUserClassName().isEmpty()) {

								// System.out.println("result bean : "+intCodeResultBean);
								generateEvent(intCodeResultBean);
							}
							// System.out.println("breaking");
							break;
						}
						if (klassName.equals(IAgentConstants.JAVA_IO_FILE)) {
							// System.out.println("javaio found");
							// System.out.println("next class : "+trace[i+1]);
							javaIoFile = true;
						}
					}
					ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
					// System.out.println(threadId + " : remove from another method");
					return;
				}

				for (int i = 0; i < trace.length; i++) {
					klassName = trace[i].getClassName();

					// if (klassName.equals(MSSQL_PREPARED_STATEMENT_CLASS)
					// || klassName.equals(MSSQL_PREPARED_BATCH_STATEMENT_CLASS)
					// || klassName.contains(MYSQL_PREPARED_STATEMENT)) {
					// intCodeResultBean.setValidationBypass(true);
					// } else
					if (IAgentConstants.MYSQL_GET_CONNECTION_MAP.containsKey(klassName)
							&& IAgentConstants.MYSQL_GET_CONNECTION_MAP.get(klassName)
									.contains(trace[i].getMethodName())) {
						intCodeResultBean.setValidationBypass(true);
					}
					if (!PATTERN.matcher(klassName).matches()) {
						JSONArray params = toString(arg, sourceString);
						if (params != null) {
							intCodeResultBean.setParameters(params);
							intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName,
									trace[i].getMethodName());
							if (i > 0)
								intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
						} else {
							ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
							// System.out.println(threadId + " : remove from another method");
							return;
						}
						break;
					}
				}
				if (intCodeResultBean.getUserClassName() != null && !intCodeResultBean.getUserClassName().isEmpty()) {
					generateEvent(intCodeResultBean);
				} else if (IAgentConstants.SYSYTEM_CALL_START.equals(sourceString)) {
					int traceId = getClassNameForSysytemCallStart(trace, intCodeResultBean);
					intCodeResultBean.setUserAPIInfo(trace[traceId].getLineNumber(), klassName,
							trace[traceId].getMethodName());
					intCodeResultBean.setParameters(toString(arg, sourceString));
					if (traceId > 0)
						intCodeResultBean.setCurrentMethod(trace[traceId - 1].getMethodName());
					generateEvent(intCodeResultBean);
				}

			}
		} catch (Exception e) {
//			e.printStackTrace();
		} finally {
			ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
		}
	}

	private int getClassNameForSysytemCallStart(StackTraceElement[] trace, JavaAgentEventBean intCodeResultBean) {
		boolean classRuntimeFound = false;
		for (int i = 0; i < trace.length; i++) {
			if (trace[i].getClassName().equals(IAgentConstants.JAVA_LANG_RUNTIME))
				classRuntimeFound = true;
			else if (classRuntimeFound)
				return i;
		}
		return -1;
	}

	/**
	 * This method is used for MSSQL parameter Extraction
	 *
	 * @param obj        the object in argument of Instrumented Method
	 * @param parameters the parameter list as a JSONArray
	 * @return void
	 * @throws NoSuchFieldException     the no such field exception
	 * @throws SecurityException        the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws IllegalAccessException   the illegal access exception
	 */
	@SuppressWarnings("unchecked")
	private static void getMSSQLParameterValue(Object obj, JSONArray parameters)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		String className = obj.getClass().getCanonicalName();

		// Extraction of Connection params
		{
			Field field = obj.getClass().getDeclaredField(MSSQL_CURRENT_OBJECT);
			field.setAccessible(true);
			Object child = field.get(obj);
			Field childField = null;

			if (child.getClass().getName().equals(MSSQL_SERVER_STATEMENT_CLASS)) {
				childField = child.getClass().getDeclaredField(MSSQL_CONNECTION_FIELD);
			} else if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
				childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_CONNECTION_FIELD);
			} else {
				childField = child.getClass().getSuperclass().getSuperclass().getDeclaredField(MSSQL_CONNECTION_FIELD);
			}
			childField.setAccessible(true);

			child = childField.get(child);
			childField = child.getClass().getDeclaredField(MSSQL_ACTIVE_CONNECTION_PROP_FIELD);
			childField.setAccessible(true);

			Properties connectionProperties = (Properties) childField.get(child);
			parameters.add(connectionProperties.toString());
		}

		// Extraction of query for different query methods
		if (className.contains(MSSQL_PREPARED_STATEMENT_CLASS)) {
			Field field = obj.getClass().getDeclaredField(MSSQL_STATEMENT_FIELD);

			field.setAccessible(true);
			Object child = field.get(obj);

			// extract Query
			Field childField = null;
			if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
				childField = child.getClass().getDeclaredField(MSSQL_USER_SQL_FIELD);
			} else {
				// for JAVA compilation before 7.1, an instance of class
				// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42 is
				// made instead of
				// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement
				childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_USER_SQL_FIELD);
			}
			childField.setAccessible(true);
			parameters.add(childField.get(child));

			ArrayList<Object[]> params = null;

			// extract Values passed to Prepared Statement
			if (className.equals(MSSQL_PREPARED_BATCH_STATEMENT_CLASS)) {

				if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
					childField = child.getClass().getDeclaredField(MSSQL_BATCH_PARAM_VALUES_FIELD);
				} else {
					childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_BATCH_PARAM_VALUES_FIELD);
				}
				childField.setAccessible(true);
				params = (ArrayList<Object[]>) childField.get(child);

			} else {

				if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
					childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_IN_OUT_PARAM_FIELD);
				} else {
					// for JAVA compilation before 7.1, an instance of class
					// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42
					// is made instead of
					// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement
					childField = child.getClass().getSuperclass().getSuperclass()
							.getDeclaredField(MSSQL_IN_OUT_PARAM_FIELD);
				}
				childField.setAccessible(true);

				Object[] outParams = (Object[]) childField.get(child);
				params = new ArrayList<Object[]>();
				params.add(outParams);
			}
			addParamValuesMSSQL(params, parameters);

		} else if (className.equals(MSSQL_STATEMENT_EXECUTE_CMD_CLASS)) {
			Field field = obj.getClass().getDeclaredField(IAgentConstants.SQL);
			field.setAccessible(true);
			parameters.add(field.get(obj));

		} else if (className.equals(MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS)) {
			Field field = obj.getClass().getDeclaredField(MSSQL_STATEMENT_FIELD);
			field.setAccessible(true);
			Object child = field.get(obj);
			Field childField = child.getClass().getDeclaredField(MSSQL_BATCH_STATEMENT_BUFFER_FIELD);
			childField.setAccessible(true);
			ArrayList<String> queries = (ArrayList<String>) childField.get(child);
			parameters.add(queries.size());
			for (Object query : queries) {
				parameters.add(query);
			}

		} else if (className.equals(MSSQL_STATEMENT_EXECUTE_CMD_CLASS)) {
			Field field = obj.getClass().getDeclaredField(MSSQL_SQL_FIELD);
			field.setAccessible(true);
			parameters.add(field.get(obj));
		} else {

		}

	}

	/**
	 * Gets the MySQL parameter values.
	 *
	 * @param args       the arguments of Instrumented Method
	 * @param parameters the parameters
	 * @return the my SQL parameter value
	 */
	@SuppressWarnings("unchecked")
	private void getMySQLParameterValue(Object[] args, JSONArray parameters, String sourceString) {
		try {
			if (arg[1] != null && !arg[1].toString().isEmpty()
					&& !sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE)) {
				parameters.add(arg[1].toString());
			} else {
				Object obj = args[0];
				if (sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE)) {
					obj = args[args.length - 1];
				}
				Class<?> objClass = obj.getClass();
				if (objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_5)
						|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_5_0_4)
						|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_42)
						|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_4)
						|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_6)
						|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_8)) {
					String id = threadId + IAgentConstants.COLON_SEPERATOR + obj.hashCode();
					String originalSql = EventThreadPool.getInstance().getMySqlPreparedStatementsMap(id);
					if (originalSql != null) {
						EventThreadPool.getInstance().setMySqlPreparedStatementsMap(id, null);
						parameters.add(originalSql);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Gets the mongo parameters.
	 *
	 * @param args       the arguments of Instrumented Method
	 * @param parameters the parameters
	 * @return the my SQL parameter value
	 * @throws NoSuchFieldException     the no such field exception
	 * @throws SecurityException        the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws IllegalAccessException   the illegal access exception
	 */
	@SuppressWarnings("unchecked")
	public static void getMongoParameterValue(Object[] args, JSONArray parameters)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		Object protocol = args[0];

		String namespace = null;
		Field f = null;

		Class<? extends Object> nsClass = protocol.getClass();
		int depth = 0;
		String keyspaceName = null;

		JSONObject queryDetailObj = new JSONObject();
		// for getting the namespace
		while (namespace == null && nsClass != null && depth < 4) {
			try {
				f = nsClass.getDeclaredField(MONGO_NAMESPACE_FIELD);
				f.setAccessible(true);
				Object ns = f.get(protocol);
				namespace = ns.toString();

				queryDetailObj.put(MONGO_NAMESPACE_FIELD, namespace);
				keyspaceName = namespace.split(IAgentConstants.DOTINSQUAREBRACKET)[1];
				if (!keyspaceName.equals(MONGO_COLLECTION_WILDCARD)) {
					queryDetailObj.put(MONGO_COLLECTION_FIELD, keyspaceName);
				}

			} catch (Exception ex) {
				nsClass = nsClass.getSuperclass();
				depth++;
			}
		}

		// for Connecter v 6.0 and above
		try {

			f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
			f.setAccessible(true);
			Object command = f.get(protocol);
			parameters.add(command.toString());
			f = protocol.getClass().getDeclaredField(MONGO_PAYLOAD_FIELD);
			f.setAccessible(true);
			Object payload = f.get(protocol);
			if (payload != null) {
				f = payload.getClass().getDeclaredField(MONGO_PAYLOAD_FIELD);
				f.setAccessible(true);
				payload = f.get(payload);
				parameters.add(payload.toString());
			}
		} catch (Exception e) {
			// for Connecter v 5.0 and below
			// fetch query parameters
			if (protocol.getClass().getName().contains(MONGO_DELETE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_DELETE_CLASS_FRAGMENT.toLowerCase());
				f = protocol.getClass().getDeclaredField(MONGO_DELETE_REQUEST_FIELD);
				f.setAccessible(true);
				List<Object> deleteRequests = (List<Object>) f.get(protocol);

				for (Object obj : deleteRequests) {
					try {
						f = obj.getClass().getDeclaredField(MOGNO_ELEMENT_DATA_FIELD);
						f.setAccessible(true);
						Object[] elementData = (Object[]) f.get(obj);

						for (Object request : elementData) {
							if (request != null) {
								f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
								f.setAccessible(true);
								Object filter = f.get(request);
								parameters.add(filter.toString());
							}
						}

					} catch (NoSuchFieldException synchedDelete) {
						f = obj.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(obj);
						parameters.add(filter.toString());
					}

				}
			} else if (protocol.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_UPDATE_CLASS_FRAGMENT.toLowerCase());
				List<Object> updates = null;
				if (protocol.getClass().getName().contains(MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT)) {
					updates = new ArrayList<Object>();
					updates.add(protocol);
				} else {
					f = protocol.getClass().getDeclaredField(MONGO_MULTIPLE_UPDATES_FIELD);
					f.setAccessible(true);
					updates = (List<Object>) f.get(protocol);
				}
				for (Object obj : updates) {
					f = obj.getClass().getDeclaredField(MONGO_FILTER_FIELD);
					f.setAccessible(true);
					Object filter = f.get(obj);
					parameters.add(filter.toString());
					f = obj.getClass().getDeclaredField(MONGO_SINGLE_UPDATE_FIELD);
					f.setAccessible(true);
					Object update = f.get(obj);
					parameters.add(update.toString());
				}
			} else if (protocol.getClass().getName().contains(MONGO_INSERT_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_INSERT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_INSERT_REQUESTS_FIELD);
				f.setAccessible(true);
				List<Object> insertRequests = (List<Object>) f.get(protocol);
				for (Object request : insertRequests) {
					f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
					f.setAccessible(true);
					Object document = f.get(request);
					parameters.add(document.toString());
				}

			} else if (protocol.getClass().getName().contains(MONGO_FIND_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_FIND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter = f.get(protocol);
				parameters.add(filter.toString());

			} else if (protocol.getClass().getName().contains(MONGO_WRITE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_WRITE_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_WRITE_REQUEST_FIELD);
				f.setAccessible(true);
				List<Object> writeRequests = (List<Object>) f.get(protocol);

				for (Object request : writeRequests) {

					if (request.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
						f = request.getClass().getDeclaredField(MONGO_SINGLE_UPDATE_FIELD);
						f.setAccessible(true);
						Object update = f.get(request);
						parameters.add(update.toString());
						f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(request);
						parameters.add(filter.toString());

						parameters.add(update.toString());
					} else if (request.getClass().getName().contains(MONGO_DELETE_CLASS_FRAGMENT)) {
						f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(request);
						parameters.add(filter.toString());

					} else {
						f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
						f.setAccessible(true);
						Object document = f.get(request);
						parameters.add(document.toString());

					}

				}

			} else if (protocol.getClass().getName().contains(MONGO_DISTINCT_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_DISTINCT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FIELD_NAME_FIELD);
				f.setAccessible(true);
				Object fieldName = f.get(protocol);
				parameters.add(fieldName.toString());
				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter = f.get(protocol);
				parameters.add(filter.toString());

			} else if (protocol.getClass().getName().contains(MONGO_COMMAND_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_COMMAND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
				f.setAccessible(true);
				Object insertRequests = f.get(protocol);
				parameters.add(insertRequests.toString());
			} else {

				// System.out.println(protocol.getClass().getName());

			}

		}
		// add Query Details
		parameters.add(queryDetailObj.toString());
	}

	/**
	 * @param obj
	 * @param parameters
	 */
	private void getClassLoaderParameterValue(Object[] args, JSONArray parameters) {
		for (Object obj : args) {
			try {
				JSONArray jsonArray = (JSONArray) parser.parse(mapper.writeValueAsString(obj));
				for (int i = 0; i < jsonArray.size(); i++) {
					String value = jsonArray.get(i).toString();
					if (value.startsWith(IAgentConstants.FILE_URL)) {
						parameters.add(value.substring(7));
					}
				}
			} catch (Exception e) {
			}
		}

	}

	/**
	 * @param            obj: this pointer object
	 * @param parameters
	 */
	private JSONArray getOracleParameterValue(Object thisPointer, JSONArray parameters, String sourceString) {

		Class<?> thisPointerClass = thisPointer.getClass();
		try {
			if (IAgentConstants.ORACLE_CLASS_SKIP_LIST.contains(thisPointerClass.getName())) {
				return null;
			}
			// in case of doRPC()
			if (thisPointerClass.getName().contains(ORACLE_CONNECTION_IDENTIFIER)) {

				Field cursorField = thisPointerClass.getDeclaredField(IAgentConstants.CURSOR);
				cursorField.setAccessible(true);
				Object cursor = cursorField.get(thisPointer);

				// ignore batch fetch events
				if (!String.valueOf(cursor).equals(IAgentConstants.ZERO) || String.valueOf(cursor).equals(IAgentConstants.NULL)) {
					return null;
				}

				Field oracleStatementField = thisPointerClass.getDeclaredField(IAgentConstants.ORACLESTATEMENT);
				oracleStatementField.setAccessible(true);
				Object oracleStatement = oracleStatementField.get(thisPointer);

				Class<?> statementKlass = oracleStatement.getClass();
				while (!statementKlass.getName().equals(ORACLE_STATEMENT_CLASS_IDENTIFIER)) {
					statementKlass = statementKlass.getSuperclass();
				}

				Field sqlObjectField = statementKlass.getDeclaredField(IAgentConstants.SQLOBJECT);
				sqlObjectField.setAccessible(true);
				Object sqlObject = sqlObjectField.get(oracleStatement);

				parameters.add(String.valueOf(sqlObject));

			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return parameters;
	}

	/**
	 * This method is used to extract All the required parameters through the
	 * arguments of instrumented method
	 * 
	 * @param obj the obj
	 * @return the JSON array
	 */
	@SuppressWarnings({ "unchecked", "unused" })
	private JSONArray toString(Object[] obj, String sourceString) {

		if (obj == null) {
			return null;
		}
		JSONArray parameters = new JSONArray();
		try {
			if (obj[0] != null && sourceString.contains(MSSQL_IDENTIFIER)) {
				getMSSQLParameterValue(obj[0], parameters);
			} else if (sourceString.contains(MYSQL_IDENTIFIER)) {
				getMySQLParameterValue(obj, parameters, sourceString);
			} else if (obj[0] != null && sourceString.contains(MONGO_IDENTIFIER)) {
				getMongoParameterValue(obj, parameters);
			} else if (obj[0] != null && sourceString.contains(ORACLE_DB_IDENTIFIER)) {
				parameters = getOracleParameterValue(arg[arg.length - 1], parameters, sourceString);
			} else if (obj[0] != null && sourceString.contains(CLASS_LOADER_IDENTIFIER)) {
				getClassLoaderParameterValue(obj, parameters);
			} else if (sourceString.equals(PSQLV3_EXECUTOR) || sourceString.equals(PSQLV2_EXECUTOR)
					|| sourceString.equals(PSQL42_EXECUTOR) || sourceString.equals(PSQLV3_EXECUTOR7_4)) {
				getPSQLParameterValue(obj, parameters);
			} else if (sourceString.equals(HSQL_V2_4)) {
				getHSQLParameterValue(obj[0], parameters);
			} else {
				for (int i = 0; i < obj.length; i++) {
					Object json = parser.parse(mapper.writeValueAsString(obj[i]));
					parameters.add(json);
				}
//				parameters.addAll((List<String>) parser.parse(mapper.writeValueAsString(obj)));
			}

		} catch (Throwable th) {
			parameters.add((obj != null) ? obj.toString() : null);
//			th.printStackTrace();
		}
		return parameters;
	}

	private void getHSQLParameterValue(Object object, JSONArray parameters) {

		try {
			Class<?> statementClass = Thread.currentThread().getContextClassLoader().loadClass(IAgentConstants.ORG_HSQLDB_STATEMENT);
			Field sqlField = statementClass.getDeclaredField(IAgentConstants.SQL);
			sqlField.setAccessible(true);
			parameters.add((String) sqlField.get(object));
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void getPSQLParameterValue(Object[] obj, JSONArray parameters) {
		String sql = IAgentConstants.EMPTY_STRING;
		if (obj.length >= 0) {
			sql = obj[0].toString();
		}
		if (obj.length >= 1) {
			Object simpleParameter = obj[1];
			Field paramValuesField;
			try {
				paramValuesField = simpleParameter.getClass().getDeclaredField(IAgentConstants.PARAMVALUES);
				paramValuesField.setAccessible(true);
				Object[] paramValues = (Object[]) paramValuesField.get(simpleParameter);
				List<Object> paramArray = new ArrayList<>();
				for (int i = 0; i < paramValues.length; i++) {
					String param = mapper.writeValueAsString(paramValues[i]);
					sql = sql.replaceFirst(IAgentConstants.PSQL_PARAMETER_REPLACEMENT, param);
					paramArray.add(param);
				}
				parameters.add(sql);
				parameters.add(paramArray);
			} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException
					| JsonProcessingException e) {
				e.printStackTrace();
			}

		}
	}

	/**
	 * Adds the Values passed to a MSSQL prepared statement into ParameterList.
	 *
	 * @param paramList  the param list
	 * @param parameters the parameters
	 * @throws NoSuchFieldException     the no such field exception
	 * @throws SecurityException        the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws IllegalAccessException   the illegal access exception
	 */
	@SuppressWarnings({ "unused", "unchecked" })
	private static void addParamValuesMSSQL(ArrayList<Object[]> paramList, JSONArray parameters)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		for (Object[] outParams : paramList) {
			JSONArray params = new JSONArray();

			for (int counter = 0; counter < outParams.length; counter++) {
				Field param = outParams[counter].getClass().getDeclaredField(MSSQL_INPUT_DTV_FIELD);
				param.setAccessible(true);
				Object value = param.get(outParams[counter]);
				param = value.getClass().getDeclaredField(MSSQL_IMPL_FIELD);
				param.setAccessible(true);
				value = param.get(value);
				param = value.getClass().getDeclaredField(MSSQL_VALUE_FIELD);
				param.setAccessible(true);
				value = param.get(value);
				params.add(value.toString());
			}
			parameters.add(params.toString());
		}
	}

	private void generateEvent(JavaAgentEventBean intCodeResultBean) {
			intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
			if (intCodeResultBean.getSource() != null && (intCodeResultBean.getSource()
					.equals(IAgentConstants.JAVA_NET_URLCLASSLOADER)
					|| intCodeResultBean.getSource().equals(IAgentConstants.JAVA_NET_URLCLASSLOADER_NEWINSTANCE))) {
				try {
					List<String> list = (List<String>) intCodeResultBean.getParameters();

					JavaAgentDynamicPathBean dynamicJarPathBean = new JavaAgentDynamicPathBean(LoggingInterceptor.applicationUUID,
							System.getProperty(IAgentConstants.USER_DIR), new ArrayList<String>(Agent.jarPathSet), list);
//					System.out.println("dynamic jar path bean : " + dynamicJarPathBean);
					eventQueue.add(dynamicJarPathBean);
				} catch (IllegalStateException e) {
					System.err.println(
							"Dropping dynamicJarPathBean event " + intCodeResultBean.getId() + " due to buffer capacity reached.");
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {
//				System.out.println("Final request map 1: " + ServletEventPool.getInstance().getRequestMap().get(this.threadId));
//				System.out.println("count: " + ServletEventPool.getInstance().getServletInfoReferenceRecord().get(threadId));
//				System.out.println("Final request map 2: " + ServletEventPool.getInstance().getRequestMap().get(this.threadId));
//				System.out.println("count: " + ServletEventPool.getInstance().getServletInfoReferenceRecord().get(threadId));
				try {
					intCodeResultBean.setServletInfo(new ServletInfo(ExecutionMap.find(this.executionId,
							ServletEventPool.getInstance().getRequestMap().get(this.threadId))));
					eventQueue.add(intCodeResultBean);

				} catch (IllegalStateException e) {
					System.err.print(
							"Dropping event " + intCodeResultBean.getId() + " due to buffer capacity reached.");
				} catch (Exception e) {
					e.printStackTrace();
					System.err.println("Thread id: " + this.threadId + ", eid: " + this.executionId + " map: "
							+ ServletEventPool.getInstance().getRequestMap().get(this.threadId));
				}

			}
		}
}
