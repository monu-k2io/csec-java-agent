/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.api.agent.security;

/**
 * The New Relic Security API Implementation. Use {@link NewRelicSecurity#getAgent} to obtain the root of a hierarchy of
 * objects offering additional capabilities.
 */
public final class NewRelicSecurity {

    private NewRelicSecurity() {
    }

    private static SecurityAgent securityAgent = Agent.getInstance();

    /**
     * Returns the root of the New Relic Security Java Agent API object hierarchy.
     *
     * @return the root of the New Relic Security Java Agent API object hierarchy
     */
    public static SecurityAgent getAgent() {
        return securityAgent;
    }


    /**
     * Indicates whether the hook processing can be done in the instrumentation modules.
     * @return {@code true} iff security module init is completed and hook processing can be allowed.
     * {@code false} otherwise.
     */
    public static boolean isHookProcessingActive(){
        return true;
    }

    /**
     * Marks the end of agent init. Hooks can now be processed.
     */
    public static void markAgentAsInitialised() {
    }
}
