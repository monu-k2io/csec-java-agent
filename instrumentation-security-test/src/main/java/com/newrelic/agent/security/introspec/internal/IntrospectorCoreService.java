package com.newrelic.agent.security.introspec.internal;

import com.newrelic.agent.InstrumentationProxy;
import com.newrelic.agent.core.CoreService;
import com.newrelic.agent.service.AbstractService;

class IntrospectorCoreService extends AbstractService implements CoreService {
    private InstrumentationProxy instrumentation = null;

    public IntrospectorCoreService() {
        super(CoreService.class.getSimpleName());
    }

    public int getShutdownCount() {
        return 0;
    }

    @Override
    public InstrumentationProxy getInstrumentation() {
        return instrumentation;
    }

    public void setInstrumentation(InstrumentationProxy instrumentationProxy) {
        instrumentation = instrumentationProxy;
    }

    @Override
    public void shutdownAsync() {
    }

    @Override
    protected void doStart() {
    }

    @Override
    protected void doStop() {
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
