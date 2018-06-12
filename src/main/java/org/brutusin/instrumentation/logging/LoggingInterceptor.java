/*
 * Copyright 2014 brutusin.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.brutusin.instrumentation.logging;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.Channels;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.brutusin.commons.json.spi.JsonCodec;
import org.brutusin.instrumentation.Interceptor;
import com.k2.org.json.simple.JSONArray;
import com.k2.org.json.simple.JSONObject;

import com.k2.org.objectweb.asm.tree.ClassNode;
import com.k2.org.objectweb.asm.tree.MethodNode;

import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;

public class LoggingInterceptor extends Interceptor {

	private File rootFile;

	private static final Set<String> methodMap;
	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	private static final Pattern PATTERN;
	private static final Set<String> executorMathods;
	private static JSONArray intCodeInterceptedResult;
	private static PrintWriter writer;
	private static Integer VMPID;

	static {
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		methodMap = new HashSet<String>(Arrays.asList(IAgentConstants.COMPLETE_LIST));
		allClasses = new HashSet<String>(Arrays.asList(IAgentConstants.ALL_CLASSES));
		executorMathods = new HashSet<String>(Arrays.asList(IAgentConstants.EXECUTORS));
		interceptMethod = new HashMap<String, List<String>>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i], new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
		}

	}

	@Override
	public void init(String arg) throws Exception {
		this.rootFile = new File("/tmp/K2-instrumentation-logging/events.sock");
		if (!rootFile.exists()) {
			throw new RuntimeException("Root doesn't exists, Please start the K2-IntCode Agent");
		}
		try {
			UnixSocketAddress address = new UnixSocketAddress(this.rootFile);
			UnixSocketChannel channel = UnixSocketChannel.open(address);
			writer = new PrintWriter(Channels.newOutputStream(channel));
			System.out.println("Connection to " + channel.getLocalAddress() + ", established successfully!!!");
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			String runningVM = runtimeMXBean.getName();
			VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf('@')));
			ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID);
			applicationInfoBean.setJvmArguments(new JSONArray(runtimeMXBean.getInputArguments()));
			writer.println(applicationInfoBean.toString());
			writer.flush();
			
		} catch (Exception e) {
		}
		intCodeInterceptedResult = new JSONArray();
	}

	@Override
	public boolean interceptClass(String className, byte[] byteCode) {
		return allClasses.contains(className);
	}

	@Override
	public boolean interceptMethod(ClassNode cn, MethodNode mn) {
		return interceptMethod.get(cn.name).contains(mn.name);
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void doOnStart(Object source, Object[] arg, String executionId) {
		String sourceString = null;
		Method m = null;
		Constructor c = null;
		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
			// System.out.println(m.toGenericString());
		} else if (source instanceof Constructor) {
			c = (Constructor) source;
			sourceString = c.toGenericString();
			// System.out.println(c.toGenericString());
		}

		if (sourceString != null && methodMap.contains(sourceString)) {
			long start = System.currentTimeMillis();

			IntCodeResultBean intCodeResultBean = new IntCodeResultBean(start, sourceString, toString(arg), VMPID);
			if (executorMathods.contains(sourceString)) {
				String klassName;
				StackTraceElement[] trace = Thread.currentThread().getStackTrace();
				for (int i = 0; i < trace.length; i++) {
					klassName = trace[i].getClassName();
					if (!PATTERN.matcher(klassName).matches()) {
						intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName, trace[i].getMethodName());
						if(i>0)
							intCodeResultBean.setCurrentMethod(trace[i-1].getMethodName());
						break;
					}
				}
				generateEvent(intCodeResultBean);
			} else
				intCodeInterceptedResult.add(intCodeResultBean);

		}
	}

	@SuppressWarnings("unchecked")
	private void generateEvent(IntCodeResultBean intCodeResultBean) {
		// trace(logFile, intCodeInterceptedResult.toString());
		intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
		intCodeInterceptedResult.add(intCodeResultBean);
		writer.println(intCodeInterceptedResult.toString());
		writer.flush();
		intCodeInterceptedResult.clear();
	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnFinish(Object source, Object result, String executionId) {
		String sourceString = null;
		Method m = null;
		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
		}

		if (IAgentConstants.MSSQL_EXECUTOR.equals(sourceString)) {
			String klassName;
			StackTraceElement[] trace = Thread.currentThread().getStackTrace();
			IntCodeResultBean intCodeResultBean = (IntCodeResultBean) intCodeInterceptedResult.get(0);
			for (int i = 0; i < trace.length; i++) {
				klassName = trace[i].getClassName();
				if (!PATTERN.matcher(klassName).matches()) {
					intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName, trace[i].getMethodName());
					if(i>0)
						intCodeResultBean.setCurrentMethod(trace[i-1].getMethodName());
					break;
				}
			}
			intCodeInterceptedResult.remove(0);
			generateEvent(intCodeResultBean);
		}
	}

	private static void trace(File f, String s) {
		if (s == null) {
			return;
		}
		try {
			FileOutputStream fos = new FileOutputStream(f, true);
			try {
				fos.write(s.getBytes());
				fos.write("\n".getBytes());
			} finally {
				fos.close();
			}
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String getParameterValue(Object obj) {
		try {
			Field f = obj.getClass().getDeclaredField("setterDTV");
			f.setAccessible(true);
			Object objx = f.get(obj);
			if (objx.getClass().getName().contains("DTV")) {
				Field f2 = objx.getClass().getDeclaredField("impl");
				f2.setAccessible(true);
				Object objA = f2.get(objx);
				if (objA.getClass().getName().contains("AppDTVImpl")) {
					f = objA.getClass().getDeclaredField("value");
					f.setAccessible(true);
					return JsonCodec.getInstance().transform(f.get(objA).toString());
				}
			}
		} catch (Exception e) {
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private static JSONArray toString(Object[] obj) {
		if (obj == null) {
			return null;
		}
		JSONArray parameters = new JSONArray();

		// StringBuilder b = new StringBuilder();
		// b.append('[');
		for (int i = 0; i < obj.length; i++) {
			if (obj[i] instanceof Object[]) {
				parameters.add(toString((Object[]) obj[i]));
			}
			// b.append(toString((Object[]) obj[i]));
			else
				try {
					if (obj[i].getClass().getName().equals("com.microsoft.sqlserver.jdbc.Parameter")) {
						JSONObject objx = new JSONObject();
						parameters.add(getParameterValue(obj[i]));
						// b.append(getParameterValue(obj[i]));
					} else {
						parameters.add(JsonCodec.getInstance().transform(obj[i]));
						// b.append(JsonCodec.getInstance().transform(obj[i]));
					}
				} catch (Throwable th) {
					parameters.add((obj[i] != null) ? JsonCodec.getInstance().transform(obj[i].toString()) : null);
				}
			// if (i != obj.length - 1)
			// b.append(',');
		}
		// b.append(']');
		// return b.toString();
		return parameters;
	}

}