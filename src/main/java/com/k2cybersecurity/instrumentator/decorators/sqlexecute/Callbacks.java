package com.k2cybersecurity.instrumentator.decorators.sqlexecute;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;

public class Callbacks {

	public static void doOnEnter(String sourceString, String className, String methodName, Object thisObject, Object[] args,
			String exectionId) {
		//        System.out.println("OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - eid : " + exectionId);
		if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null) {

					if (args != null && args.length > 0) {
						ThreadLocalDBMap.getInstance()
								.create(thisObject, args[0].toString(), className, sourceString, exectionId,
										Instant.now().toEpochMilli(), false, false);
					}
					if (ThreadLocalDBMap.getInstance().get(thisObject) != null) {
						EventDispatcher.dispatch(new ArrayList<>(ThreadLocalDBMap.getInstance().get(thisObject)),
								VulnerabilityCaseType.SQL_DB_COMMAND);
						ThreadLocalDBMap.getInstance().clear(thisObject);
					} else {
						System.err.println(
								String.format("Null SQL query fired : %s : %s : %s : %s", sourceString, exectionId,
										Arrays.asList(args), args.length));
					}
				}
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}

	public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
			Object returnVal, String exectionId) {
		//        System.out.println("OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
//		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
	}

	public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
			Throwable error, String exectionId) throws Throwable {
		if(!ThreadLocalOperationLock.getInstance().isAcquired()) {
			try {
				ThreadLocalOperationLock.getInstance().acquire();
				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
						+ " - error : " + error + " - eid : " + exectionId);
			} finally {
				ThreadLocalOperationLock.getInstance().release();
			}
		}
	}
}
