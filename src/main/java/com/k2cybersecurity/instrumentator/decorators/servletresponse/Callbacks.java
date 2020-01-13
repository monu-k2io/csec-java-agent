package com.k2cybersecurity.instrumentator.decorators.servletresponse;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import org.apache.commons.lang3.StringUtils;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
//        System.out.println("Came to servletresponse hook :" + exectionId + " :: " + sourceString);
        if (!ThreadLocalHttpMap.getInstance().isServiceMethodEncountered() && !ThreadLocalOperationLock.getInstance()
                .isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (obj == null && args != null && args.length == 1 && args[0] != null) {
//                    System.out.println("Setting response  : " + exectionId);
                    ThreadLocalHttpMap.getInstance().setHttpResponse(args[0]);
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (obj !=null && ThreadLocalHttpMap.getInstance().getHttpResponse()!=null && ThreadLocalHttpMap.getInstance().getHttpResponse().hashCode() == obj.hashCode()) {
//                    System.out.println("Came to servletresponse hook exit :" + exectionId + " :: " + sourceString + " :: " + obj + " :: " + returnVal);
                    if (StringUtils.equals(methodName, "getWriter")) {
                        ThreadLocalHttpMap.getInstance().setResponseWriter(returnVal);
//                        System.out.println("reponseWriter set kar diya. :" + exectionId + " :: " + ThreadLocalHttpMap.getInstance().getResponseWriter());
                        ThreadLocalHTTPIOLock.getInstance().resetLock();

                    } else if (StringUtils.equals(methodName, "getOutputStream")) {
                        ThreadLocalHttpMap.getInstance().setResponseOutputStream(returnVal);
                        ThreadLocalHTTPIOLock.getInstance().resetLock();

                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//						+ " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}
