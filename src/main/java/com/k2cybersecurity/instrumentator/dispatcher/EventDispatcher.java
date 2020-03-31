package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.custom.K2CyberSecurityException;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalDBMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalExecutionMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.models.operationalbean.AbstractOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.FileOperationalBean;
import com.k2cybersecurity.intcodeagent.models.operationalbean.SQLOperationalBean;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class EventDispatcher {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST = "Dropping event due to corrupt/incomplete HTTP request : ";
    public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT = "Dropping event due to empty object : ";
    public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST1 = "Dropping event due to corrupt/incomplete HTTP request : ";
    public static final String DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST2 = "Dropping event due to corrupt/incomplete HTTP request : ";
    public static final String DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1 = "Dropping event due to empty object : ";
    public static final String STRING_3_COLON = " ::: ";
    public static final String EVENT_RESPONSE_TIME_TAKEN = "Event response time taken : ";
    public static final String DOUBLE_COLON_SEPERATOR = " :: ";
    public static final String EVENT_RESPONSE_TIMEOUT_FOR = "Event response timeout for : ";
    public static final String SCHEDULING_FOR_EVENT_RESPONSE_OF = "Scheduling for event response of : ";
    public static final String ERROR = "Error: ";
    public static final String ID_PLACEHOLDER = "{{ID}}";
    public static final String ACCESS_BY_BLOCKED_IP_ADDRESS_DETECTED_S = "Access by blocked IP address detected : %s";
    public static String ATTACK_PAGE_CONTENT = StringUtils.EMPTY;
    public static String BLOCK_PAGE_CONTENT = StringUtils.EMPTY;


    static {
        try {
            InputStream attackPageStream = ClassLoader.getSystemResourceAsStream("attack.html");
            if (attackPageStream == null) {
                logger.log(LogLevel.ERROR, "Unable to locate attack.html.", EventDispatcher.class.getSimpleName());
            } else {
                ATTACK_PAGE_CONTENT = IOUtils.toString(attackPageStream, StandardCharsets.UTF_8);
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Error reading attack.html :", e, EventDispatcher.class.getSimpleName());
        }

        try {
            InputStream attackPageStream = ClassLoader.getSystemResourceAsStream("block.html");
            if (attackPageStream == null) {
                logger.log(LogLevel.ERROR, "Unable to locate block.html.", EventDispatcher.class.getSimpleName());
            } else {
                BLOCK_PAGE_CONTENT = IOUtils.toString(attackPageStream, StandardCharsets.UTF_8);
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Error reading block.html :", e, EventDispatcher.class.getSimpleName());
        }
    }

    public static void dispatch(AbstractOperationalBean objectBean, VulnerabilityCaseType vulnerabilityCaseType)
            throws K2CyberSecurityException {
        boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
        if (!ret) {
            logger.log(LogLevel.ERROR,
                    DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
                    EventDispatcher.class.getName());
            return;
        }
        // Place dispatch here
//		printDispatch(objectBean);
        // TODO: implement check if the object bean is logically enpty based on case
        // type or implement a isEmpty method in each operation bean.
        if (!objectBean.isEmpty()) {
            DispatcherPool.getInstance().dispatchEvent(
                    new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                    new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
                    Thread.currentThread().getStackTrace(), objectBean, vulnerabilityCaseType);
            submitAndHoldForEventResponse(objectBean.getExecutionId());
            checkIfClientIPBlocked();
        } else {
            logger.log(
                    LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBean,
                    EventDispatcher.class.getName());
        }
    }


    public static void dispatch(List<SQLOperationalBean> objectBeanList, VulnerabilityCaseType vulnerabilityCaseType, String exectionId)
            throws K2CyberSecurityException {
        boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
        if (!ret) {
            logger.log(
                    LogLevel.ERROR, DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST1
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + objectBeanList,
                    EventDispatcher.class.getName());
            return;
        }
        // Place dispatch here

        List<SQLOperationalBean> toBeSentBeans = new ArrayList<>();
        objectBeanList.forEach((bean) -> {
            SQLOperationalBean beanChecked = ThreadLocalDBMap.getInstance().checkAndUpdateSentSQLCalls(bean);
            if (beanChecked != null && !beanChecked.isEmpty()) {
                toBeSentBeans.add(bean);
            }
        });
//		printDispatch(toBeSentBeans);
        if (!toBeSentBeans.isEmpty()) {
            DispatcherPool.getInstance().dispatchEvent(
                    new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                    new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
                    Thread.currentThread().getStackTrace(), toBeSentBeans, vulnerabilityCaseType);
            submitAndHoldForEventResponse(exectionId);
            checkIfClientIPBlocked();
        }
    }


    private static void printDispatch(List<SQLOperationalBean> objectBeanList) {
        System.out.println("Bean list : " + objectBeanList);
    }

    public static void dispatch(DeployedApplication deployedApplication, VulnerabilityCaseType vulnerabilityCaseType) {
        if (!deployedApplication.isEmpty()) {
            DispatcherPool.getInstance().dispatchAppInfo(deployedApplication, vulnerabilityCaseType);
        } else {
//			System.out.println("Application info found to be empty : " + deployedApplication);
        }
    }

    public static void dispatch(HttpRequestBean httpRequestBean, String sourceString, String exectionId, long startTime,
                                VulnerabilityCaseType reflectedXss) throws K2CyberSecurityException {
//		System.out.println("Passed to XSS detection : " + exectionId + " :: " + httpRequestBean.toString()+ " :: " + httpRequestBean.getHttpResponseBean().toString());
        if (!httpRequestBean.isEmpty()) {
            DispatcherPool.getInstance().dispatchEvent(httpRequestBean, sourceString, exectionId, startTime,
                    Thread.currentThread().getStackTrace(), reflectedXss);
            submitAndHoldForEventResponse(exectionId);
            checkIfClientIPBlocked();
        }
    }

    public static void dispatch(FileOperationalBean fileOperationalBean, FileIntegrityBean fbean,
                                VulnerabilityCaseType fileOperation) throws K2CyberSecurityException {
        boolean ret = ThreadLocalHttpMap.getInstance().parseHttpRequest();
        if (!ret) {
            logger.log(
                    LogLevel.ERROR, DROPPING_EVENT_DUE_TO_CORRUPT_INCOMPLETE_HTTP_REQUEST2
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + fileOperationalBean,
                    EventDispatcher.class.getName());
            return;
        }
        // Place dispatch here
//		printDispatch(objectBean);

        // TODO: implement check if the object bean is logically enpty based on case
        // type or implement a isEmpty method in each operation bean.
        if (!fileOperationalBean.isEmpty()) {
            DispatcherPool.getInstance().dispatchEvent(
                    new HttpRequestBean(ThreadLocalExecutionMap.getInstance().getHttpRequestBean()),
                    new AgentMetaData(ThreadLocalExecutionMap.getInstance().getMetaData()),
                    Thread.currentThread().getStackTrace(), fileOperationalBean, fbean, fileOperation);
            submitAndHoldForEventResponse(fileOperationalBean.getExecutionId());
            checkIfClientIPBlocked();
        } else {
            logger.log(
                    LogLevel.ERROR, DROPPING_EVENT_DUE_TO_EMPTY_OBJECT1
                            + ThreadLocalExecutionMap.getInstance().getHttpRequestBean() + STRING_3_COLON + fileOperationalBean,
                    EventDispatcher.class.getName());

        }
    }

    private static boolean submitAndHoldForEventResponse(String executionId) throws K2CyberSecurityException {
        if (!ProtectionConfig.getInstance().getProtectKnownVulnerableAPIs()) {
            return false;
        }
        logger.log(LogLevel.INFO, SCHEDULING_FOR_EVENT_RESPONSE_OF + executionId, EventDispatcher.class.getSimpleName());

        EventResponse eventResponse = new EventResponse(executionId);
        AgentUtils.getInstance().getEventResponseSet().put(executionId, eventResponse);
        try {
            eventResponse.getResponseSemaphore().acquire();
            if (eventResponse.getResponseSemaphore().tryAcquire(1000, TimeUnit.MILLISECONDS)) {
                logger.log(LogLevel.INFO,
                        EVENT_RESPONSE_TIME_TAKEN + eventResponse.getEventId() + DOUBLE_COLON_SEPERATOR + (
                                eventResponse.getReceivedTime() - eventResponse.getGenerationTime()) + DOUBLE_COLON_SEPERATOR + executionId,
                        EventDispatcher.class.getSimpleName());
                if (eventResponse.isAttack()) {
                    sendK2AttackPage(eventResponse.getEventId());
                    throw new K2CyberSecurityException(eventResponse.getResultMessage());
                }
                return true;
            } else {
                logger.log(LogLevel.WARNING, EVENT_RESPONSE_TIMEOUT_FOR + executionId, EventDispatcher.class.getSimpleName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
        } finally {
            AgentUtils.getInstance().getEventResponseSet().remove(executionId);
        }
        return false;
    }

    private static void sendK2AttackPage(String eventId) {
        try {
            if (ThreadLocalHttpMap.getInstance().getHttpResponse() != null) {
                String attackPage = StringUtils.replace(ATTACK_PAGE_CONTENT, ID_PLACEHOLDER, eventId);
                logger.log(LogLevel.WARNING,"Sending K2 Attack page for : " + eventId, EventDispatcher.class.getName());
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    OutputStream outputStream = (OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream();
                    outputStream.write(attackPage.getBytes());
                    outputStream.flush();
                    outputStream.close();
                } else if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    PrintWriter printWriter = (PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter();
                    printWriter.println(attackPage);
                    printWriter.flush();
                    printWriter.close();
                } else {
                    Object resp = ThreadLocalHttpMap.getInstance().getHttpResponse();
                    try {
                        Method getOutputStream = resp.getClass().getMethod("getOutputStream");
                        getOutputStream.setAccessible(true);
                        OutputStream outputStream = (OutputStream) getOutputStream.invoke(resp);
                        outputStream.write(attackPage.getBytes());
                        outputStream.flush();
                        outputStream.close();
                    } catch (Throwable e) {
                        Method getWriter = resp.getClass().getMethod("getWriter");
                        getWriter.setAccessible(true);
                        PrintWriter printWriter = (PrintWriter) getWriter.invoke(resp);
                        printWriter.println(attackPage);
                        printWriter.flush();
                        printWriter.close();
                    }
                }
            } else {
                logger.log(LogLevel.ERROR, "Unable to locate response object for this attack.", EventDispatcher.class.getSimpleName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Unable to process response for this attack.", e, EventDispatcher.class.getSimpleName());

        } finally {
            try {
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    ((OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream()).close();
                }
                if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    ((PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter()).close();
                }
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
            }
        }

    }

    private static void sendK2BlockPage(String ip) {
        try {
            if (ThreadLocalHttpMap.getInstance().getHttpResponse() != null) {
                String attackPage = StringUtils.replace(BLOCK_PAGE_CONTENT, ID_PLACEHOLDER, ip);
                logger.log(LogLevel.WARNING,"Sending K2 Blocking page to : " + ip, EventDispatcher.class.getName());
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    OutputStream outputStream = (OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream();
                    outputStream.write(attackPage.getBytes());
                    outputStream.flush();
                    outputStream.close();
                } else if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    PrintWriter printWriter = (PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter();
                    printWriter.println(attackPage);
                    printWriter.flush();
                    printWriter.close();
                } else {
                    Object resp = ThreadLocalHttpMap.getInstance().getHttpResponse();
                    try {
                        Method getOutputStream = resp.getClass().getMethod("getOutputStream");
                        getOutputStream.setAccessible(true);
                        OutputStream outputStream = (OutputStream) getOutputStream.invoke(resp);
                        outputStream.write(attackPage.getBytes());
                        outputStream.flush();
                        outputStream.close();
                    } catch (Throwable e) {
                        Method getWriter = resp.getClass().getMethod("getWriter");
                        getWriter.setAccessible(true);
                        PrintWriter printWriter = (PrintWriter) getWriter.invoke(resp);
                        printWriter.println(attackPage);
                        printWriter.flush();
                        printWriter.close();
                    }
                }
            } else {
                logger.log(LogLevel.ERROR, "Unable to locate response object for this attack.", EventDispatcher.class.getSimpleName());
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, "Unable to process response for this attack.", e, EventDispatcher.class.getSimpleName());

        } finally {
            try {
                if (ThreadLocalHttpMap.getInstance().getResponseOutputStream() != null) {
                    ((OutputStream) ThreadLocalHttpMap.getInstance().getResponseOutputStream()).close();
                }
                if (ThreadLocalHttpMap.getInstance().getResponseWriter() != null) {
                    ((PrintWriter) ThreadLocalHttpMap.getInstance().getResponseWriter()).close();
                }
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, ERROR, e, EventDispatcher.class.getSimpleName());
            }
        }

    }

    private static void checkIfClientIPBlocked() throws K2CyberSecurityException {
        if (ProtectionConfig.getInstance().getAutoAttackIPBlockingXFF() && AgentUtils.getInstance().isBlockedIP(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP())) {
            sendK2BlockPage(ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP());
            throw new K2CyberSecurityException(String.format(ACCESS_BY_BLOCKED_IP_ADDRESS_DETECTED_S, ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getClientIP()));
        }
    }
}