package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.javaagent.HttpRequestBean;
import okhttp3.*;
import okhttp3.Request.Builder;
import okhttp3.internal.http.HttpMethod;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.Map.Entry;

public class RequestUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static Request generateK2Request(HttpRequestBean httpRequestBean) {
        logger.log(LogLevel.DEBUG, String.format("Firing request : %s", httpRequestBean), RequestUtils.class.getName());
        StringBuilder url = new StringBuilder(String.format("%s://localhost", httpRequestBean.getProtocol()));
        url.append(":");
        url.append(httpRequestBean.getServerPort());
        url.append(httpRequestBean.getUrl());

        RequestBody requestBody = null;

        if (StringUtils.isNotBlank(httpRequestBean.getContentType())) {
            if (httpRequestBean.getParameterMap() != null && !httpRequestBean.getParameterMap().isEmpty()) {
                FormBody.Builder builder = new FormBody.Builder();
                for (Entry<String, String[]> param : httpRequestBean.getParameterMap().entrySet()) {
                    for (int i = 0; i < param.getValue().length; i++) {
                        builder.add(param.getKey(), param.getValue()[i]);
                    }
                }
                requestBody = builder.build();
            } else {
                requestBody = RequestBody.create(MediaType.parse(httpRequestBean.getContentType()),
                        httpRequestBean.getBody());
            }
        } else if (StringUtils.equalsIgnoreCase(httpRequestBean.getMethod(), "POST")) {
            requestBody = RequestBody.create(null,
                    httpRequestBean.getBody());
        }

        Builder requestBuilder = new Request.Builder();
        requestBuilder = requestBuilder.url(url.toString());

        if (HttpMethod.permitsRequestBody(httpRequestBean.getMethod())) {
            requestBuilder = requestBuilder.method(httpRequestBean.getMethod(), requestBody);
        } else {
            requestBuilder = requestBuilder.method(httpRequestBean.getMethod(), null);
        }
        requestBuilder = requestBuilder.headers(Headers.of((Map<String, String>) httpRequestBean.getHeaders()));

        return requestBuilder.build();
    }

}
