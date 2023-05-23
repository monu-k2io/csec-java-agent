package com.newrelic.api.agent.security.schema;

public class ApplicationURLMapping {
    private String method;
    private String url;

    public ApplicationURLMapping(String method, String url) {
        this.method = method;
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof ApplicationURLMapping) {
            ApplicationURLMapping mapping = (ApplicationURLMapping) obj;
            return url.equals(mapping.url) && method.equals(mapping.method);
        }
        return false;
    }

    public String toString() {
        return "Method: " + method + ", Url: " + url;
    }
}
