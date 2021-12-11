package com.k2cybersecurity.instrumentator.decorators.jndi;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalJNDILock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SSRFOperationalBean;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class Callbacks {

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) throws K2CyberSecurityException {
        if (!ThreadLocalOperationLock.getInstance().isAcquired() && !ThreadLocalJNDILock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
                if (ThreadLocalHttpMap.getInstance().getHttpRequest() != null && args != null && args.length == 1) {

                    ThreadLocalJNDILock.getInstance().acquire(obj, sourceString, exectionId);
                    List<String> references = new ArrayList<>();

                    if (args[0] instanceof String) {
                        references.add((String) args[0]);
                    } else {
                        try {
                            Method getAll = args[0].getClass().getMethod("getAll");
                            getAll.setAccessible(true);
                            Enumeration<String> allNames = (Enumeration<String>) getAll.invoke(args[0]);
                            while (allNames.hasMoreElements()) {
                                references.add(allNames.nextElement());
                            }
                        } catch (Exception e) {
                        }
                    }

                    for (String reference : references) {
                        try {
                            URI url = new URI(reference);
                            if (StringUtils.equals("file", url.getScheme()) || StringUtils.isBlank(url.getScheme())) {
                                handleFileAccess(url.getPath(), className, sourceString, exectionId, methodName);
                            } else {
                                handleSSRF(reference, className, sourceString, exectionId, methodName);
                            }
                        } catch (Exception e) {
                            handleFileAccess(reference, className, sourceString, exectionId, methodName);
                        }
                    }
                }
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    private static void handleFileAccess(String reference, String className, String sourceString, String exectionId, String methodName) throws K2CyberSecurityException {
        EventDispatcher.dispatch(new FileOperationalBean(reference, className,
                sourceString, exectionId, Instant.now().toEpochMilli(), false, methodName), VulnerabilityCaseType.FILE_OPERATION);

    }

    private static void handleSSRF(String reference, String className, String sourceString, String exectionId, String methodName) throws K2CyberSecurityException {
        EventDispatcher.dispatch(new SSRFOperationalBean(reference, className, sourceString, exectionId,
                Instant.now().toEpochMilli(), methodName), VulnerabilityCaseType.HTTP_REQUEST);
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && ThreadLocalJNDILock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            ThreadLocalJNDILock.getInstance().release(obj, sourceString, exectionId);
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty()
                && ThreadLocalJNDILock.getInstance().isAcquired(obj, sourceString, exectionId)) {
            ThreadLocalJNDILock.getInstance().release(obj, sourceString, exectionId);
        }
    }
}
