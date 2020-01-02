package com.k2cybersecurity.instrumentator.dispatcher;

import com.k2cybersecurity.instrumentator.AgentNew;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.logging.ProcessorThread;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.models.operationalbean.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.ObjectInputStream;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

public class Dispatcher implements Runnable {

    private static final Pattern PATTERN;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    private HttpRequestBean httpRequestBean;
    private AgentMetaData metaData;
    private Object event;
    private StackTraceElement[] trace;
    private VulnerabilityCaseType vulnerabilityCaseType;

    static {
        PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
    }

    public Dispatcher(HttpRequestBean httpRequestBean, AgentMetaData metaData, StackTraceElement[] trace, Object event,
                      VulnerabilityCaseType vulnerabilityCaseType) {
        this.httpRequestBean = httpRequestBean;
        this.metaData = metaData;
        this.event = event;
        this.trace = trace;
        this.vulnerabilityCaseType = vulnerabilityCaseType;
    }

    public Dispatcher(Object event,
                      VulnerabilityCaseType vulnerabilityCaseType) {
        this.event = event;
        this.vulnerabilityCaseType = vulnerabilityCaseType;
    }

    @Override
    public void run() {
        printDispatch();
        if (event == null) {
            System.out.println("------- Invalid event -----------");
            return;
        }

        if(vulnerabilityCaseType.equals(VulnerabilityCaseType.APP_INFO)) {
            // TODO: Handle SHA & size calculation for deployed application bean here.
            DeployedApplication deployedApplication = (DeployedApplication) event;

            return;
        }
        JavaAgentEventBean eventBean = prepareEvent(httpRequestBean, metaData, vulnerabilityCaseType);
        switch (vulnerabilityCaseType) {
            case FILE_OPERATION:
                FileOperationalBean fileOperationalBean = (FileOperationalBean) event;
                eventBean = setGenericProperties(fileOperationalBean, eventBean);
                eventBean = prepareFileEvent(eventBean, fileOperationalBean);
                if (allowedExtensionFileIO(eventBean.getParameters(), eventBean.getSourceMethod())) {
                    System.out.println("------- Event ByPass -----------");
                    return;
                }
                break;
            case SYSTEM_COMMAND:
                ForkExecOperationalBean operationalBean = (ForkExecOperationalBean) event;
                eventBean = setGenericProperties(operationalBean, eventBean);
                eventBean = prepareSystemCommandEvent(eventBean, operationalBean);
                break;
            case SQL_DB_COMMAND:
                List<SQLOperationalBean> operationalList = (List<SQLOperationalBean>) event;
                if (operationalList.isEmpty()) {
                    System.out.println("------- Invalid event -----------");
                    return;
                }
                eventBean = setGenericProperties(operationalList.get(0), eventBean);
                eventBean = prepareSQLDbCommandEvent(operationalList, eventBean);
                break;

            case NOSQL_DB_COMMAND:
                NoSQLOperationalBean noSQLOperationalBean = (NoSQLOperationalBean) event;
                eventBean = setGenericProperties(noSQLOperationalBean, eventBean);
                eventBean = prepareNoSQLEvent(eventBean, noSQLOperationalBean);
                break;

            default:

        }
        eventBean = processStackTrace(eventBean);
        eventBean.setEventGenerationTime(Instant.now().toEpochMilli());
        EventSendPool.getInstance().sendEvent(eventBean.toString());
        System.out.println("============= Event Start ============");
        System.out.println(eventBean);
        System.out.println("============= Event End ============");
    }

    private JavaAgentEventBean prepareSQLDbCommandEvent(List<SQLOperationalBean> operationalList,
                                                        JavaAgentEventBean eventBean) {
        JSONArray params = new JSONArray();
        for (SQLOperationalBean operationalBean : operationalList) {
            JSONObject query = new JSONObject();
            query.put("query", operationalBean.getQuery());
            query.put("parameters", new JSONObject(operationalBean.getParams()));
            params.add(query);
        }
        eventBean.setParameters(params);
        return eventBean;
    }

    private JavaAgentEventBean prepareSystemCommandEvent(JavaAgentEventBean eventBean,
                                                         ForkExecOperationalBean operationalBean) {
        JSONArray params = new JSONArray();
        params.add(operationalBean.getCommand());
        if (operationalBean.getEnvironment() != null) {
            params.add(new JSONObject(operationalBean.getEnvironment()));
        }
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareFileEvent(JavaAgentEventBean eventBean,
                                                       FileOperationalBean fileOperationalBean) {
        JSONArray params = new JSONArray();
        params.add(fileOperationalBean.getFileName());
        eventBean.setParameters(params);
        return eventBean;
    }

    private static JavaAgentEventBean prepareNoSQLEvent(JavaAgentEventBean eventBean,
                                                        NoSQLOperationalBean noSQLOperationalBean) {
        JSONArray params = new JSONArray();
        ProcessorThread.getMongoDbParameterValue(noSQLOperationalBean.getApiCallArgs(), params);
        eventBean.setParameters(params);
        return eventBean;
    }

    private boolean allowedExtensionFileIO(JSONArray params, String sourceString) {
        if (JAVA_IO_FILE_INPUTSTREAM_OPEN.equals(sourceString)) {
            for (int i = 0; i < params.size(); i++) {
                String filePath = params.get(i).toString();
                String extension = StringUtils.EMPTY;

                int k = filePath.lastIndexOf('.');
                if (k > 0) {
                    extension = filePath.substring(k + 1).toLowerCase();

                }
                if (ALLOWED_EXTENSIONS.contains(extension))
                    return true;
            }
        }
        return false;
    }

    private JavaAgentEventBean processStackTrace(JavaAgentEventBean eventBean) {
        String lastNonJavaClass = StringUtils.EMPTY;
        String lastNonJavaMethod = StringUtils.EMPTY;
        int lastNonJavaLineNumber = 0;
        String klassName = null;
        boolean userclassFound = false;

        for (int i = 0; i < trace.length; i++) {
            int lineNumber = trace[i].getLineNumber();
            klassName = trace[i].getClassName();
            rciTriggerCheck(i, eventBean, klassName);
            deserializationTriggerCheck(i, eventBean, klassName);
            if (lineNumber <= 0) {
                continue;
            }
            Matcher matcher = PATTERN.matcher(klassName);
            if (!matcher.matches() && !userclassFound) {
                eventBean.setUserAPIInfo(lineNumber, klassName, trace[i].getMethodName());
                if (i > 0) {
                    eventBean.setCurrentMethod(trace[i - 1].getMethodName());
                }
                userclassFound = true;
            } else if (!userclassFound && StringUtils.isNotBlank(matcher.group(5))) {
                lastNonJavaClass = trace[i].getClassName();
                lastNonJavaMethod = trace[i].getMethodName();
                lastNonJavaLineNumber = trace[i].getLineNumber();
            }
        }
        if (eventBean.getUserFileName() == null || eventBean.getUserFileName().isEmpty()) {
            eventBean.setUserAPIInfo(lastNonJavaLineNumber, lastNonJavaClass, lastNonJavaMethod);
        }
        return eventBean;
    }

    private void deserializationTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
        if (ObjectInputStream.class.getName().equals(klassName)
                && StringUtils.equals(trace[index].getMethodName(), READ_OBJECT)) {
            eventBean.getMetaData().setTriggerViaDeserialisation(true);
            logger.log(LogLevel.DEBUG, String.format("Printing stack trace for deserialise event : %s : %s",
                    eventBean.getId(), Arrays.asList(trace)), ProcessorThread.class.getName());

        }
    }

    private void rciTriggerCheck(int index, JavaAgentEventBean eventBean, String klassName) {
        if (!StringUtils.contains(trace[index].toString(), ".java:") && index > 0
                && StringUtils.contains(trace[index - 1].toString(), ".java:")) {
            eventBean.getMetaData().setTriggerViaRCI(true);
            eventBean.getMetaData().getRciMethodsCalls().add(trace[index].toString());
            eventBean.getMetaData().getRciMethodsCalls().add(trace[index - 1].toString());
            logger.log(LogLevel.DEBUG, String.format("Printing stack trace for probable rci event : %s : %s",
                    eventBean.getId(), Arrays.asList(trace)), ProcessorThread.class.getName());
        }
        if (StringUtils.contains(klassName, REFLECT_NATIVE_METHOD_ACCESSOR_IMPL)
                && StringUtils.equals(trace[index].getMethodName(), INVOKE_0) && index > 0) {
            eventBean.getMetaData().setTriggerViaRCI(true);
            eventBean.getMetaData().getRciMethodsCalls().add(trace[index - 1].toString());
            logger.log(LogLevel.DEBUG, String.format("Printing stack trace for rci event : %s : %s", eventBean.getId(),
                    Arrays.asList(trace)), ProcessorThread.class.getName());
        }
    }

    private static JavaAgentEventBean setGenericProperties(AbstractOperationalBean objectBean,
                                                           JavaAgentEventBean eventBean) {
        eventBean.setApplicationUUID(AgentNew.APPLICATION_UUID);
        eventBean.setPid(AgentNew.VMPID);
        eventBean.setSourceMethod(objectBean.getSourceMethod());
        eventBean.setId(objectBean.getExecutionId());
        eventBean.setStartTime(objectBean.getStartTime());
        return eventBean;
    }

    private static JavaAgentEventBean prepareEvent(HttpRequestBean httpRequestBean, AgentMetaData metaData,
                                                   VulnerabilityCaseType vulnerabilityCaseType) {
        JavaAgentEventBean eventBean = new JavaAgentEventBean();
        eventBean.setHttpRequest(httpRequestBean);
        eventBean.setMetaData(metaData);
        eventBean.setCaseType(vulnerabilityCaseType.getCaseType());
        return eventBean;
    }

    public static String getDbName(String className) {
        if (StringUtils.contains(className, "sqlserver."))
            return "MSSQL";
        else if (StringUtils.contains(className, "mysql."))
            return "MYSQL";
        else if (StringUtils.contains(className, "hsqldb."))
            return "HSQL";
        else if (StringUtils.contains(className, "postgresql."))
            return "POSTGRESQL";
        else if (StringUtils.contains(className, "firebirdsql."))
            return "FIREBIRD";
        else if (StringUtils.contains(className, "h2."))
            return "H2";
        else if (StringUtils.contains(className, "derby."))
            return "DERBY";
        else if (StringUtils.contains(className, "ibm.db2."))
            return "IBMDB2";
        else if (StringUtils.contains(className, "teradata."))
            return "TERADATA";
        else if (StringUtils.contains(className, "oracle.jdbc."))
            return "ORACLE";
        else if (StringUtils.contains(className, "mariadb."))
            return "MARIADB";
        else
            return "UNKNOWN";

    }

    public void printDispatch() {
        System.out
                .println("==========================================================================================");

        System.out.println("Intercepted Request : " + httpRequestBean);

        System.out.println("Agent Meta : " + metaData);

        System.out.println("Intercepted transaction : " + event);

        System.out.println("Trace : " + Arrays.asList(trace));

        System.out.println("vulnerabilityCaseType : " + vulnerabilityCaseType);

        System.out
                .println("==========================================================================================");
    }

}
