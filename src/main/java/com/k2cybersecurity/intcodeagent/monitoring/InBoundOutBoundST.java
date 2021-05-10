package com.k2cybersecurity.intcodeagent.monitoring;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpConnectionStat;
import com.k2cybersecurity.intcodeagent.models.javaagent.OutBoundHttp;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class InBoundOutBoundST {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    final private static Object lock = new Object();
    public static final String PRESENT_IN_CACHE_HTTP_CONNECTION = "present in cache http connection ";
    public static final String ADDING_HTTP_CONNECTION = "Adding http connection ";
    public static final String CONNECTION_LIST_FOR_POSTING = "Connection List for posting ";

    private ScheduledExecutorService inOutExecutorService;

    private static InBoundOutBoundST instance;

    private Map<Integer, OutBoundHttp> cache;

    private Set<OutBoundHttp> newConnections;

    public Map<Integer, OutBoundHttp> getCache() {
        return cache;
    }

    public Set<OutBoundHttp> getNewConnections() {
        return newConnections;
    }

    public boolean addOutBoundHTTPConnection(OutBoundHttp outBoundHttp) {
        if (getCache().containsKey(outBoundHttp.getHashCode())) {
            logger.log(LogLevel.DEBUG, PRESENT_IN_CACHE_HTTP_CONNECTION + outBoundHttp, InBoundOutBoundST.class.getName());
            OutBoundHttp cachedHttpCon = cache.get(outBoundHttp.getHashCode());
            cachedHttpCon.getCount().incrementAndGet();
            return false;
        } else {
            cache.put(outBoundHttp.getHashCode(), new OutBoundHttp(outBoundHttp));
            logger.log(LogLevel.DEBUG, ADDING_HTTP_CONNECTION + outBoundHttp, InBoundOutBoundST.class.getName());
            return newConnections.add(outBoundHttp);
        }
    }

    private InBoundOutBoundST() {
        inOutExecutorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(Thread.currentThread().getThreadGroup(), r,
                        "K2-inbound-outbound-st");
            }
        });
        inOutExecutorService.scheduleAtFixedRate(runnable, 2, 2, TimeUnit.HOURS);
        cache = new HashMap<>();
        newConnections = new HashSet<>();
        logger.log(LogLevel.INFO, "in-bound out-bound monitor thread started successfully!!!", InBoundOutBoundST.class.getName());
    }

    public static InBoundOutBoundST getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new InBoundOutBoundST();
                }
            }
        }
        return instance;
    }

    private Runnable runnable = new Runnable() {

        @Override
        public void run() {
            task(cache.values(), true);
            cache.clear();
        }
    };

    public static void task(Collection<OutBoundHttp> allConnections, boolean isCached) {
        /**
         * Create JSON
         * Send to IC
         * Clear cache
         * */
        logger.log(LogLevel.DEBUG, CONNECTION_LIST_FOR_POSTING + allConnections, InBoundOutBoundST.class.getName());
        List<OutBoundHttp> outBoundHttps = new ArrayList<>(allConnections);
        for (int i = 0; i < outBoundHttps.size(); i += 40) {
            int maxIndex = Math.min(i + 40, outBoundHttps.size());
            HttpConnectionStat httpConnectionStat = new HttpConnectionStat(outBoundHttps.subList(i, maxIndex), K2Instrumentator.APPLICATION_UUID, isCached);
            EventSendPool.getInstance().sendEvent(httpConnectionStat.toString());
        }
    }


    public void clearNewConnections() {
        newConnections.clear();
    }
}
