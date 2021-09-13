package com.k2cybersecurity.instrumentator.decorators.ldaplibs;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.LDAPOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.time.Instant;

public class Callbacks {

//	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String executionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//				System.out.println(
//						"sourceString : " + sourceString + " args : " + Arrays.asList(args) + " this : " + obj);

                switch (sourceString) {
                    case ILDAPConstants.APACHE_LDAP_1:
                    case ILDAPConstants.APACHE_LDAP_2:
                        searchMethodApacheLib(sourceString, className, methodName, obj, args, executionId);
                        break;
                    case ILDAPConstants.UNBOUNDID_IN_MEMORY:
                    case ILDAPConstants.UNBOUNDID_LDAP_CONNECTION:
                        searchMethodUnboundidLib(sourceString, className, methodName, obj, args, executionId);
                        break;
                    case ILDAPConstants.LDAPTIVE_EXECUTE:
                        executeMethodLdaptive(sourceString, className, methodName, obj, args, executionId);
                        break;
                    default:
                        break;

                }

//				logger.log(LogLevel.INFO,
//						"OnEnter :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//								+ " - eid : " + executionId, Callbacks.class.getName());
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void executeMethodLdaptive(String sourceString, String className, String methodName, Object obj,
                                              Object[] args, String executionId) {
        try {
            Object searchRequestObj = args[0];

            Method getBaseDnMethod = searchRequestObj.getClass().getDeclaredMethod("getBaseDn");
            getBaseDnMethod.setAccessible(true);
            Object baseDNObj = getBaseDnMethod.invoke(searchRequestObj);
            String dnValue = StringUtils.EMPTY;
            if (baseDNObj != null) {
                dnValue = (String) baseDNObj;
            }
            Method getFilterMethod = searchRequestObj.getClass().getMethod("getFilter");
            getFilterMethod.setAccessible(true);
            Object filterObject = getFilterMethod.invoke(searchRequestObj);
            LDAPOperationalBean ldapOperationalBean = ThreadLocalLdaptiveMap.getInstance().get(filterObject);
            if (ldapOperationalBean != null) {
                ldapOperationalBean.setName(dnValue);
//				System.out.println("DN is : " + dnValue + " filter is : " + ldapOperationalBean.getFilter());
                EventDispatcher.dispatch(ldapOperationalBean, VulnerabilityCaseType.LDAP);
            }

        } catch (Exception | K2CyberSecurityException e) {
            e.printStackTrace();
        }

    }

    private static void searchMethodUnboundidLib(String sourceString, String className, String methodName, Object obj,
                                                 Object[] args, String executionId) {
        try {
            Object searchRequestObj = args[0];
            Method getBaseDNMethod = searchRequestObj.getClass().getDeclaredMethod("getBaseDN");
            getBaseDNMethod.setAccessible(true);
            Object baseDNObj = getBaseDNMethod.invoke(searchRequestObj);
            String dnValue = StringUtils.EMPTY;
            if (baseDNObj != null) {
                dnValue = (String) baseDNObj;
            }

            Method getFilterMethod = searchRequestObj.getClass().getDeclaredMethod("getFilter");
            getFilterMethod.setAccessible(true);
            Object filterObj = getFilterMethod.invoke(searchRequestObj);
            String filterValue = StringUtils.EMPTY;
            if (filterObj != null) {
                filterValue = filterObj.toString();
            }

//			System.out.println("DN is : " + dnValue + " filter is : " + filterValue);

            if (StringUtils.isNotBlank(dnValue) && StringUtils.isNotBlank(filterValue)
                    && ThreadLocalLDAPMap.getInstance().put(filterValue)) {
                LDAPOperationalBean ldapOperationalBean = new LDAPOperationalBean(dnValue, filterValue, className,
                        sourceString, executionId, Instant.now().toEpochMilli(), methodName);
                EventDispatcher.dispatch(ldapOperationalBean, VulnerabilityCaseType.LDAP);
            }
        } catch (Exception | K2CyberSecurityException e) {
            e.printStackTrace();
        }

    }

    private static void searchMethodApacheLib(String sourceString, String className, String methodName, Object obj,
                                              Object[] args, String executionId) {

        try {
            Object searchOperationContextObject = args[0];
            Method getFilterMethod = searchOperationContextObject.getClass().getMethod("getFilter");
            getFilterMethod.setAccessible(true);
            Object filterObject = getFilterMethod.invoke(searchOperationContextObject);
            String filterValue = StringUtils.EMPTY;
            if (filterObject != null) {
                filterValue = filterObject.toString();
//				System.out.println("Filter value obtained : " + filterValue);
            }

            Method getDNMethod = searchOperationContextObject.getClass().getMethod("getDn");
            getDNMethod.setAccessible(true);
            Object dnObject = getDNMethod.invoke(searchOperationContextObject);
            String dnNormalizedValue = StringUtils.EMPTY;
            String dnValue = StringUtils.EMPTY;
            if (dnObject != null) {
                dnNormalizedValue = dnObject.toString();
//				System.out.println("dnNormalizedValue obtained : " + dnNormalizedValue);
                Method getUpNameMethod = dnObject.getClass().getMethod("getUpName");
                getUpNameMethod.setAccessible(true);
                Object dnObjectNotNormalized = getUpNameMethod.invoke(dnObject);
                if (dnObjectNotNormalized != null) {
                    dnValue = dnObjectNotNormalized.toString();
//					System.out.println("dnValue obtained : " + dnValue);
                }
            } else {
//				System.err.println("NULL DN OBJECT");
            }
            if (StringUtils.isNotBlank(dnValue) && StringUtils.isNotBlank(filterValue)
                    && ThreadLocalLDAPMap.getInstance().put(filterValue)) {
                LDAPOperationalBean ldapOperationalBean = new LDAPOperationalBean(dnValue, filterValue, className,
                        sourceString, executionId, Instant.now().toEpochMilli(), methodName);
                EventDispatcher.dispatch(ldapOperationalBean, VulnerabilityCaseType.LDAP);
            }
        } catch (Exception | K2CyberSecurityException e) {
            e.printStackTrace();
        }

    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled()
                && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                EventDispatcher.dispatchExitEvent(exectionId, VulnerabilityCaseType.LDAP);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
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

//public com.unboundid.ldap.sdk.SearchResult com.unboundid.ldap.sdk.LDAPConnection.search(com.unboundid.ldap.sdk.SearchRequest) throws com.unboundid.ldap.sdk.LDAPSearchException
