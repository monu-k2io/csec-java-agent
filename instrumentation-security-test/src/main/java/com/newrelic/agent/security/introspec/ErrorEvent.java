/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.introspec;

public interface ErrorEvent extends Event {

    String getErrorClass();

    String getErrorMessage();

    String getTransactionName();

}
