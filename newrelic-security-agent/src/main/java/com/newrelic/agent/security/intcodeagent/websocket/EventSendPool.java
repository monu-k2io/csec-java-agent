package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.javaagent.JavaAgentEventBean;

import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class EventSendPool {

    /**
     * Thread pool executor.
     */
    private ThreadPoolExecutor executor;

    private static EventSendPool instance;

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public Map<String, Long> getEventMap() {
        return eventMap;
    }

    private Map<String, Long> eventMap = new ConcurrentHashMap<>();
    private AtomicBoolean isWaiting = new AtomicBoolean(false);

    private EventSendPool() {
        // load the settings
        int queueSize = 1500;
        int maxPoolSize = 1;
        int corePoolSize = 1;
        long keepAliveTime = 60;

        TimeUnit timeUnit = TimeUnit.SECONDS;

        boolean allowCoreThreadTimeOut = false;

        executor = new ThreadPoolExecutor(corePoolSize, maxPoolSize, keepAliveTime, timeUnit,
                new LinkedBlockingQueue<Runnable>(queueSize), new EventAbortPolicy()) {
            @Override
            protected void afterExecute(Runnable r, Throwable t) {
                if (r instanceof Future<?>) {
                    try {
                        Future<?> future = (Future<?>) r;
                        if (future.isDone()) {
                            future.get();
                        }
                    } catch (Throwable e) {
                        AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
                    }
                }
                super.afterExecute(r, t);
            }
        };
        executor.allowCoreThreadTimeOut(allowCoreThreadTimeOut);
        executor.setThreadFactory(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(Thread.currentThread().getThreadGroup(), r,
                        "NR-CSEC-EventSender");
                t.setDaemon(true);
                return t;
            }
        });
    }

    /**
     * @return the instance
     */
    public static EventSendPool getInstance() {
        if (instance == null)
            instance = new EventSendPool();
        return instance;
    }

    public void sendEvent(String event) {
        executor.submit(new EventSender(event));
    }

    public void sendEvent(JavaAgentEventBean event) {
        executor.submit(new EventSender(event));
        AgentInfo.getInstance().getJaHealthCheck().incrementEventSentCount();
    }

    public void sendEvent(Object event) {
        executor.submit(new EventSender(event));
    }

    public static void shutDownPool() {
        if (instance != null) {
            instance.shutDownThreadPoolExecutor();
        }
        instance = null;
    }

    public void shutDownThreadPoolExecutor() {

        if (executor != null) {
            try {
                executor.shutdown(); // disable new tasks from being submitted
                if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                    // wait for termination for a timeout
                    executor.shutdownNow(); // cancel currently executing tasks

                    if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
                        logger.log(LogLevel.SEVERE, "Thread pool executor did not terminate",
                                EventSendPool.class.getName());
                    }
                }
            } catch (InterruptedException e) {
            }
        }

    }

    public static class EventAbortPolicy implements RejectedExecutionHandler {
        /**
         * Creates an {@code ValidationAbortPolicy}.
         */
        public EventAbortPolicy() {
        }

        /**
         * Always throws RejectedExecutionException.
         *
         * @param r the runnable task requested to be executed
         * @param e the executor attempting to execute this task
         * @throws RejectedExecutionException always
         */
        public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
            logger.log(LogLevel.FINER, "Event Task " + r.toString() + " rejected from  " + e.toString(), EventSendPool.class.getName());
            AgentInfo.getInstance().getJaHealthCheck().incrementDropCount();
            AgentInfo.getInstance().getJaHealthCheck().incrementProcessedCount();
        }
    }

    public AtomicBoolean isWaiting() {
        return isWaiting;
    }

    public ThreadPoolExecutor getExecutor() {
        return executor;
    }
}
