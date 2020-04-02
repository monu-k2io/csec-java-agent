package com.k2cybersecurity.instrumentator.decorators.jettyhandle;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.CallbackUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

public class Callbacks {

    public static final String SEPARATOR_COLON = ":";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
//        System.out.println("OnEnter Initial:" + sourceString + " - this : " + obj + " - eid : " + exectionId);

        // TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED
        // hook advice should be generated from Code with very specific checks.
        // Doing checks here will degrade performance.
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalHTTPServiceLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " + args[2] + " :: " + args[3]);
                if (args != null && args.length == 4 && args[2] != null && args[3] != null) {
                    if (CallbackUtils.checkArgsTypeHeirarchy(args[2], args[3])) {
                        CallbackUtils.cleanUpAllStates();
//                        System.out.println("Came to service hook 1:" + exectionId + " :: " + sourceString + " :: " + args[2] + " :: " + args[3]);
                        ThreadLocalHTTPServiceLock.getInstance().acquire(obj, sourceString, exectionId);
                        ThreadLocalHttpMap.getInstance().setHttpRequest(args[2]);
                        ThreadLocalHttpMap.getInstance().setHttpResponse(args[3]);
                        ThreadLocalHttpMap.getInstance().setServiceMethodEncountered(true);
                        ThreadLocalHttpMap.getInstance().parseHttpRequest();
                        EventDispatcher.checkIfClientIPBlocked();
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws K2CyberSecurityException {

//        System.out.println("OnExit Initial:" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

        if (!ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHTTPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
                onHttpTermination(sourceString, exectionId);
            } finally {
                ThreadLocalHTTPServiceLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }

    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[]
            args,
                                 Throwable error, String exectionId) throws Throwable {
//        System.out.println("OnError Initial:" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj.hashCode() + " - error : " + error + " - eid : " + exectionId);

        if (!ThreadLocalOperationLock.getInstance().isAcquired() && ThreadLocalHTTPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - error : " + error + " - eid : " + exectionId);
                onHttpTermination(sourceString, exectionId);
            } finally {
                ThreadLocalHTTPServiceLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void onHttpTermination(String sourceString, String exectionId) throws K2CyberSecurityException {
        try {
            if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
                ThreadLocalHttpMap.getInstance().parseHttpRequest();
                ThreadLocalHttpMap.getInstance().parseHttpResponse();
                CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
                //            CallbackUtils.checkForReflectedXSS(ThreadLocalExecutionMap.getInstance().getHttpRequestBean());
                //            System.out.println("Passing to XSS detection : " + exectionId + " :: " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString()+ " :: " + ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString());
                ThreadLocalHttpMap.getInstance().printInterceptedRequestResponse();
                if (!ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().isEmpty()) {
                    EventDispatcher.dispatch(new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                            sourceString, exectionId, Instant.now().toEpochMilli(), VulnerabilityCaseType.REFLECTED_XSS);
                    String tid = StringUtils.substringBefore(exectionId, SEPARATOR_COLON);
                }
            }
        } finally {

            // Clean up
            CallbackUtils.cleanUpAllStates();
        }
    }


}
