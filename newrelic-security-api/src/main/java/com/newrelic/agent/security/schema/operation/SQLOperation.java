package com.newrelic.agent.security.schema.operation;

import com.newrelic.agent.security.schema.AbstractOperation;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class SQLOperation extends AbstractOperation {

    private String query;

    private Map<Integer, String> params;

    private String dbName;

    private boolean isPreparedCall;

    public SQLOperation() {
        super();
        this.query = EMPTY;
        this.params = new HashMap<>();
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public Map<Integer, String> getParams() {
        return params;
    }

    public void setParams(Map<Integer, String> params) {
        this.params = params;
    }

    public boolean isPreparedCall() {
        return isPreparedCall;
    }

    public void setPreparedCall(boolean preparedCall) {
        isPreparedCall = preparedCall;
    }

    @Override
    public boolean isEmpty() {
        if (query == null || query.trim().isEmpty()) {
            return true;
        } else if (isPreparedCall) {
            return query.contains("?") && params.isEmpty();
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        SQLOperation that = (SQLOperation) o;
        return query.equals(that.query) && params.equals(that.params);
    }

    @Override
    public int hashCode() {
        return Objects.hash(query, params);
    }

    /**
     * @return the dbName
     */
    public String getDbName() {
        return dbName;
    }

    /**
     * @param dbName the dbName to set
     */
    public void setDbName(String dbName) {
        this.dbName = dbName;
    }
}

