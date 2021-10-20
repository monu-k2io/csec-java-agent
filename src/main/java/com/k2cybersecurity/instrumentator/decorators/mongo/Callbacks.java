package com.k2cybersecurity.instrumentator.decorators.mongo;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.NoSQLOperationalBean;
import org.json.simple.JSONObject;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Set;



public class Callbacks {
    final static String PAYLOAD_HOLDER = "payload";
    final static String PAYLOAD_TYPE_HOLDER = "payload";
    // This is an exhaustive list of operation types
    // we would be able to identify on from command arg
    final static String[] MONGO_OPERATIONS = {
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

    /**
     * Class to hold and maintain a MongoPayload structure
     */
    static class MongoPayload {
        private Object payload = null;
        private String payloadType = "Unknown";

        MongoPayload(final Object payload) {
            this.payload = payload;
        }

        MongoPayload(final Object payload,final String payloadType) {
            this.payload = payload;
            this.payloadType = payloadType;
        }

        public void setPayload(final Object payload) {
            this.payload = payload;
        }

        public void setPayloadType(final String payloadType) {
            this.payloadType = payloadType;
        }

        public JSONObject getJSON() {
            JSONObject obj = new JSONObject();
            obj.put(PAYLOAD_HOLDER, this.payload);
            obj.put(PAYLOAD_TYPE_HOLDER, this.payloadType);
            return obj;
        }
    }

    /**
     * Responsible to generate payload from streaming payload
     * parameter to Mongo's `CommandMessage` constructor.
     * @param args
     * @param streamingPayloadIndex
     * @return
     * @throws Exception
     */
    static MongoPayload formDataFromStreamingPayload(Object[] args, final int streamingPayloadIndex) throws Exception {
        if (streamingPayloadIndex >0 && args[streamingPayloadIndex] != null) {
            Method getPayload = args[streamingPayloadIndex].getClass().getMethod("getPayload");
            getPayload.setAccessible(true);
            List<Object> payload = (List<Object>) getPayload.invoke(args[streamingPayloadIndex]);
            Method getPayloadName = args[streamingPayloadIndex].getClass().getMethod("getPayloadName");
            getPayloadName.setAccessible(true);
            String payloadName = (String) getPayloadName.invoke(args[streamingPayloadIndex]);
            MongoPayload data = new MongoPayload(payload, payloadName);
            return data;
        }
        return null;
    }

    /**
     * Responsible to generate payload from command
     * parameter to Mongo's `CommandMessage` constructor.
     * @param args
     * @return
     * @throws Exception
     */
    static MongoPayload formDataFromCommand(Object[] args) throws Exception {
        Method toString = args[1].getClass().getMethod("toString");
        toString.setAccessible(true);
        MongoPayload data = new MongoPayload(toString.invoke(args[1]));
        Method getKeySet = args[1].getClass().getMethod("keySet");
        getKeySet.setAccessible(true);
        Set<String> keys = (Set<String>) getKeySet.invoke(args[1]);
        for (String op : MONGO_OPERATIONS) {
            if(keys.contains(op)) {
                data.setPayloadType(op);
                break;
            }
        }
        return data;
    }

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException, Exception {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()
                && args != null
        ) {
            ThreadLocalOperationLock.getInstance().acquire();
            int streamingPayloadIndex = -1;
            try {
                switch(args.length) {
                    // For version 3.6.x - 3.12.x
                    case 9:
                        streamingPayloadIndex = 6;
                        break;
                    // For version 4.x and above
                    case 10:
                        streamingPayloadIndex = 7;
                        break;
                    default:
                }
                MongoPayload data = formDataFromStreamingPayload(args, streamingPayloadIndex);
                if (data == null) {
                    data = formDataFromCommand(args);
                }
                if (data != null) {
                    EventDispatcher.dispatch(new NoSQLOperationalBean(data.getJSON(), className, sourceString, exectionId,
                            Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.NOSQL_DB_COMMAND);
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
