package org.springframework.web.reactive.result.method;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.ApplicationURLMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.util.pattern.PathPattern;

import java.util.Iterator;

public class SpringHelper {
    public static <T> void gatherURLMappings(T mapping){
        try {
            RequestMappingInfo mappingInfo = (RequestMappingInfo) mapping;
            Iterator<RequestMethod> methods = mappingInfo.getMethodsCondition().getMethods().iterator();
            while (methods.hasNext()) {
                for (PathPattern url : mappingInfo.getPatternsCondition().getPatterns()) {
                    if(!url.equals(""))
                        NewRelicSecurity.getAgent().addURLMapping(new ApplicationURLMapping(methods.next().name(), url.getPatternString()));
                }
            }
        } catch (Throwable e){
            System.out.println("URL_MAPPINGS_ERROR");
            e.printStackTrace();
        }
    }
}
