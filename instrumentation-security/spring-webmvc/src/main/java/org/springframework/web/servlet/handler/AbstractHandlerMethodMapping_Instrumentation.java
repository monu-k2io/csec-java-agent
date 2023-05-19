package org.springframework.web.servlet.handler;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import org.springframework.context.ApplicationContext;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.util.List;

@Weave(type = MatchType.ExactClass, originalName = "org.springframework.web.servlet.handler.AbstractHandlerMethodMapping")
public abstract class AbstractHandlerMethodMapping_Instrumentation<T> {

    protected void registerHandlerMethod(Object handler, Method method, T mapping) {
        try {
            Weaver.callOriginal();
        } finally {
            SpringHelper.gatherURLMappings(mapping);
        }
    }
}