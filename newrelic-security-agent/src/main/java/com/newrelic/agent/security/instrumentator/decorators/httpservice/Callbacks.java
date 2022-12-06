package com.newrelic.agent.security.instrumentator.decorators.httpservice;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.custom.*;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.CallbackUtils;
import com.newrelic.agent.security.intcodeagent.models.javaagent.AgentMetaData;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpRequestBean;
import com.newrelic.agent.security.intcodeagent.models.javaagent.VulnerabilityCaseType;
import org.apache.commons.lang3.StringUtils;

import java.time.Instant;

public class Callbacks {

    public static final String SEPARATOR_COLON = ":";

    public static void doOnEnter(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
//         System.out.println("OnEnter :" + sourceString + " - this : " + obj + " - eid : " + exectionId);

        // TODO: Need more checks here to assert the type of args. Maybe the TYPE_BASED
        // hook advice should be generated from Code with very specific checks.
        // Doing checks here will degrade performance.

//		if (ThreadLocalHttpMap.getInstance().isServiceMethodEncountered()) {
//			ThreadLocalExecutionMap.getInstance().getMetaData().setCurrentGenericServletInstance(obj);
//			ThreadLocalExecutionMap.getInstance().getMetaData().setCurrentGenericServletMethodName(methodName);
//		}
        ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(classRef);
        ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);
        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && !ThreadLocalHTTPDoFilterLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);

                ThreadLocalHTTPDoFilterLock.getInstance().resetLock();
                ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
                ThreadLocalHTTPDoFilterLock.getInstance().acquire(obj, sourceString, exectionId);
                ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletInstance(classRef);
                ThreadLocalHTTPDoFilterMap.getInstance().setCurrentGenericServletMethodName(methodName);
                ThreadLocalHTTPDoFilterMap.getInstance()
                        .setCurrentGenericServletStackLength(Thread.currentThread().getStackTrace().length);

            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && !ThreadLocalHTTPServiceLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("Came to service hook :" + exectionId + " :: " + sourceString + " :: " +args[0]+ " :: " +args[1]);
                if (args != null && args.length == 2 && args[0] != null && args[1] != null) {
                    if (CallbackUtils.checkArgsTypeHeirarchy(args[0], args[1])) {
                        CallbackUtils.cleanUpAllStates();
//                        System.out.println("Came to service hook 1:" + exectionId + " :: " + sourceString + " :: " + args[0] + " :: " + args[1]);
                        ThreadLocalHTTPServiceLock.getInstance().acquire(obj, sourceString, exectionId);
                        AgentInfo.getInstance().getJaHealthCheck().incrementHttpRequestCount();
                        ThreadLocalHttpMap.getInstance().setHttpRequest(args[0]);
                        ThreadLocalHttpMap.getInstance().setHttpResponse(args[1]);
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

    public static void doOnExit(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) throws K2CyberSecurityException {

//        System.out.println("OnExit Initial:" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalHTTPDoFilterLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
                ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
            } finally {
                ThreadLocalHTTPDoFilterLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalHTTPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
                onHttpTermination(sourceString, exectionId, classRef.getName(), methodName);
            } finally {
                ThreadLocalHTTPServiceLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }

    }

    public static void doOnError(String sourceString, Class<?> classRef, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
//        System.out.println("OnError Initial:" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj.hashCode()	+ " - error : " + error + " - eid : " + exectionId);

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalHTTPDoFilterLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                 System.out.println("OnExit :" + sourceString + " - this : " + obj + " - return : " + returnVal + " - eid : " + exectionId);
                ThreadLocalHTTPDoFilterMap.getInstance().cleanUp();
            } finally {
                ThreadLocalHTTPDoFilterLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }

        if (!ThreadLocalOperationLock.getInstance().isAcquired()
                && ThreadLocalHTTPServiceLock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//		System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//				+ " - error : " + error + " - eid : " + exectionId);
                onHttpTermination(sourceString, exectionId, classRef.getName(), methodName);
            } finally {
                ThreadLocalHTTPServiceLock.getInstance().release(obj, sourceString, exectionId);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void onHttpTermination(String sourceString, String exectionId, String className, String methodName) throws K2CyberSecurityException {
        try {
            if (!ThreadLocalHttpMap.getInstance().isEmpty()) {
                ThreadLocalHttpMap.getInstance().parseHttpRequest();
                ThreadLocalHttpMap.getInstance().parseHttpResponse();
                CallbackUtils.checkForFileIntegrity(ThreadLocalExecutionMap.getInstance().getFileLocalMap());
                // CallbackUtils.checkForReflectedXSS(ThreadLocalExecutionMap.getInstance().getHttpRequestBean());
                // System.out.println("Passing to XSS detection : " + exectionId + " :: " +
                // ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString()+
                // " :: " +
                // ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().toString());
                ThreadLocalHttpMap.getInstance().printInterceptedRequestResponse();
                if (!ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getHttpResponseBean().isEmpty() ||
                        (AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
                    EventDispatcher.dispatch(
                            new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                            new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
                            sourceString, exectionId, Instant.now().toEpochMilli(),
                            VulnerabilityCaseType.REFLECTED_XSS, className, methodName);
                    String tid = StringUtils.substringBefore(exectionId, SEPARATOR_COLON);
                }
            }
        } finally {

            // Clean up
            CallbackUtils.cleanUpAllStates();
        }
    }

}
