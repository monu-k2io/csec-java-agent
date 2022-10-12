package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import com.k2cybersecurity.intcodeagent.controlcommand.ControlCommandProcessor;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.properties.K2JAVersionInfo;
import com.k2cybersecurity.intcodeagent.utils.CommonUtils;
import org.java_websocket.WebSocket;
import org.java_websocket.WebSocketImpl;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.ZoneId;

public class WSClient extends WebSocketClient {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String SENDING_EVENT = "sending event: ";
    public static final String UNABLE_TO_SEND_EVENT = "Unable to send event : ";
    public static final String ERROR_IN_WSOCK_CONNECTION = "Error in WSock connection : ";
    public static final String CONNECTION_CLOSED_BY = "Connection closed by ";
    public static final String REMOTE_PEER = "remote peer.";
    public static final String LOCAL = "local.";
    public static final String CODE = " Code: ";
    public static final String REASON = " Reason: ";
    public static final String UNABLE_TO_PROCESS_INCOMING_MESSAGE = "Unable to process incoming message : ";
    public static final String DUE_TO_ERROR = " : due to error : ";
    public static final String RECONNECTING_TO_IC = "Reconnecting to IC";
    public static final String COLON_STRING = " : ";

    private static WSClient instance;

    private WebSocketImpl connection = null;

    private boolean isConnected = false;

    private WSClient() throws URISyntaxException {
        super(new URI(CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()));
        this.setTcpNoDelay(true);
        this.setConnectionLostTimeout(30);
        this.addHeader("K2-CONNECTION-TYPE", "LANGUAGE_COLLECTOR");
        this.addHeader("K2-API-ACCESSOR", CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getApiAccessorToken());
        this.addHeader("K2-VERSION", K2JAVersionInfo.collectorVersion);
        this.addHeader("K2-COLLECTOR-TYPE", "JAVA");
        this.addHeader("K2-BUILD-NUMBER", K2JAVersionInfo.buildNumber);
        this.addHeader("K2-GROUP", AgentUtils.getInstance().getGroupName());
        this.addHeader("K2-APPLICATION-UUID", K2Instrumentator.APPLICATION_UUID);
        this.addHeader("K2-JSON-VERSION", K2JAVersionInfo.jsonVersion);
    }

    /**
     * Connects to K2 intcode over a websocket channel with the configuration provided in the constructor itself.
     *
     * @throws InterruptedException
     */
    public void openConnection() throws InterruptedException {
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.INIT_WS_CONNECTION, CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getValidatorServiceEndpointURL()),
                WSClient.class.getName());
        connectBlocking();
        WebSocket conn = getConnection();
        if (conn instanceof WebSocketImpl) {
            this.connection = (WebSocketImpl) conn;
        }
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.WS_CONNECTION_SUCCESSFUL, this.getRemoteSocketAddress()) , WSClient.class.getName());
//		logger.log(LogLevel.INFO, "Current WSock ready status : {0},{1},{2}",
//				new Object[] { this.isOpen(), this.isClosing(), this.isClosed() });
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.SENDING_APPLICATION_INFO_ON_WS_CONNECT, K2Instrumentator.APPLICATION_INFO_BEAN) , WSClient.class.getName());
        super.send(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
        CommonUtils.fireUpdatePolicyAPI(AgentUtils.getInstance().getAgentPolicy());
//		Agent.allClassLoadersCount.set(0);
//		Agent.jarPathSet.clear();
//		logger.log(LogLevel.INFO, "Resetting allClassLoadersCount to " + Agent.allClassLoadersCount.get(),
//				WSClient.class.getName());
        isConnected = true;
//        WSReconnectionST.cancelTask(false);
        logger.logInit(LogLevel.INFO, String.format(IAgentConstants.APPLICATION_INFO_SENT_ON_WS_CONNECT, K2Instrumentator.APPLICATION_INFO_BEAN), WSClient.class.getName());
    }

    @Override
    public void onMessage(String message) {
        // Receive communication from IC side.
        try {
            ControlCommandProcessor.processControlCommand(message, System.currentTimeMillis());
        } catch (Throwable e) {
            logger.log(LogLevel.FATAL, UNABLE_TO_PROCESS_INCOMING_MESSAGE + message + DUE_TO_ERROR, e,
                    WSClient.class.getName());
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        isConnected = false;
        logger.log(LogLevel.WARN, CONNECTION_CLOSED_BY + (remote ? REMOTE_PEER : LOCAL) + CODE + code
                + REASON + reason, WSClient.class.getName());
        if (code == CloseFrame.NEVER_CONNECTED) {
            return;
        }

        if (code != CloseFrame.POLICY_VALIDATION) {
            WSReconnectionST.getInstance().submitNewTaskSchedule();
        } else {
            InstrumentationUtils.shutdownLogic(true);
        }
    }

    @Override
    public void onError(Exception ex) {
//        logger.log(LogLevel.SEVERE, "Error in WSock connection : " + ex.getMessage() + " : " + ex.getCause(),
//                WSClient.class.getName());
        logger.logInit(LogLevel.FATAL, String.format(IAgentConstants.WS_CONNECTION_UNSUCCESSFUL, this.getRemoteSocketAddress()),
                ex,
                WSClient.class.getName());
    }

    @Override
    public void send(String text) {
        if (this.isOpen()) {
            logger.log(LogLevel.DEBUG, SENDING_EVENT + text, WSClient.class.getName());
            super.send(text);
        } else {
            logger.log(LogLevel.DEBUG, UNABLE_TO_SEND_EVENT + text, WSClient.class.getName());
        }
    }

    @Override
    public void onWebsocketPing(WebSocket conn, Framedata f) {
        logger.log(LogLevel.DEBUG, String.format("received ping  at %s sending pong", Instant.now().atZone(ZoneId.of("UTC")).toLocalTime()), WSClient.class.getName());
        if (connection != null) {
            connection.updateLastPong();
        }
        super.onWebsocketPing(conn, f);
    }

    /**
     * @return the instance
     * @throws URISyntaxException
     */
    public static WSClient getInstance() throws URISyntaxException, InterruptedException {
        if (instance == null) {
            instance = new WSClient();
        }
        return instance;
    }

    /**
     * @return the instance
     * @throws URISyntaxException
     * @throws InterruptedException
     */
    public static WSClient reconnectWSClient() throws URISyntaxException, InterruptedException {
        logger.log(LogLevel.WARN, RECONNECTING_TO_IC,
                WSClient.class.getName());
        if (instance != null) {
            instance.closeBlocking();
        }
        instance = new WSClient();
        instance.openConnection();
        return instance;
    }

    public static boolean isConnected() {
        if (instance != null) {
            return instance.isConnected;
        }
        return false;
    }
}
