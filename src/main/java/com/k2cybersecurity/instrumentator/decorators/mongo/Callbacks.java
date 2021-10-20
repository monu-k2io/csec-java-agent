package com.k2cybersecurity.instrumentator.decorators.mongo;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.NoSQLOperationalBean;
import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;

public class Callbacks {
    static String[] mongoOperations = {
            "aggregate",
            "count",
            "createIndexes",
            "distinct",
            "drop",
            "dropIndexes",
            "find",
            "inline",
            "mapreduce",
            "parallelCollectionScan"
    };
    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && args != null
        ) {
            // For version 3.6.x - 3.12.x
            ThreadLocalOperationLock.getInstance().acquire();
            try {
                if (args.length == 9) {

                    if (args[6] != null) {
                        Method getPayload = args[6].getClass().getMethod("getPayload");
                        getPayload.setAccessible(true);
                        List<Object> payload = (List<Object>) getPayload.invoke(args[6]);
                        Method getPayloadName = args[6].getClass().getMethod("getPayloadName");
                        getPayloadName.setAccessible(true);
                        String payloadName = (String) getPayloadName.invoke(args[6]);
                        JSONObject data = new JSONObject();
                        data.put("payload", payload);
                        data.put("payloadType", payloadName);
                        EventDispatcher.dispatch(new NoSQLOperationalBean(data, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
                    } else if (args[1] != null) {
                        JSONObject payload = (JSONObject) new JSONParser().parse((String) args[1]);
                        JSONObject data = new JSONObject();
                        data.put("payload", payload);
                        for (String op : mongoOperations) {
                            payload.keySet().contains(op);
                            data.put("payloadType", op);
                            break;
                        }
                        EventDispatcher.dispatch(new NoSQLOperationalBean(data, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);

                    }


                    // For version 4.x +
                } else if (args.length == 10) {

                    ThreadLocalOperationLock.getInstance().acquire();
                    if (args[7] != null) {
                        Method getPayload = args[7].getClass().getMethod("getPayload");
                        getPayload.setAccessible(true);
                        List<Object> payload = (List<Object>) getPayload.invoke(args[7]);
                        Method getPayloadName = args[7].getClass().getMethod("getPayloadName");
                        getPayloadName.setAccessible(true);
                        String payloadName = (String) getPayloadName.invoke(args[6]);
                        JSONObject data = new JSONObject();
                        data.put("payload", payload);
                        data.put("payloadType", payloadName);
                        EventDispatcher.dispatch(new NoSQLOperationalBean(data, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
                    } else if (args[1] != null) {
                        JSONObject payload = (JSONObject) new JSONParser().parse((String) args[1]);
                        JSONObject data = new JSONObject();
                        data.put("payload", payload);
                        for (String op : mongoOperations) {
                            payload.keySet().contains(op);
                            data.put("payloadType", op);
                            break;
                        }
                        EventDispatcher.dispatch(new NoSQLOperationalBean(data, className, sourceString, exectionId,
                                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);

                    }

                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println(
////						"OnExit :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj + " - return : "
////								+ returnVal + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {

//		if(!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
//			try {
//				ThreadLocalOperationLock.getInstance().acquire();
////				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
////						+ " - error : " + error + " - eid : " + exectionId);
//			} finally {
//				ThreadLocalOperationLock.getInstance().release();
//			}
//		}
    }
}
