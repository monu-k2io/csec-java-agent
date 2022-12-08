/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.weaver.*;
import com.nr.instrumentation.security.javaio.Helper;

@Weave(type = MatchType.BaseClass, originalName = "java.io.InputStream")
public abstract class InputStream_Instrumentation {

    @NewField
    public Boolean inputStreamDataGatheringAllowed;

    @NewField
    public boolean cascadedCall;

    public int read(byte[] b) throws IOException {
        int returnData = -1;
        boolean currentCascadedCall = cascadedCall;

        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        postProcessSecurityHook(b, currentCascadedCall, 0, returnData);

        // Normal return
        return returnData;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int returnData = -1;
        boolean currentCascadedCall = cascadedCall;
        // Preprocess Phase
        preprocessSecurityHook(currentCascadedCall);

        // Actual Call
        try {
            returnData = Weaver.callOriginal();
        } finally {
            cascadedCall = currentCascadedCall;
        }

        // Postprocess Phase
        postProcessSecurityHook(b, currentCascadedCall, off, returnData);

        // Normal return
        return returnData;
    }


    private void preprocessSecurityHook(boolean currentCascadedCall) {
        try {
            if(Boolean.FALSE.equals(inputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
//                System.out.println("Start IS2 "+ this.hashCode());
            if(inputStreamDataGatheringAllowed == null) {
                inputStreamDataGatheringAllowed = Helper.processRequestInputStreamHookData(this.hashCode());
            }

            if (inputStreamDataGatheringAllowed && !currentCascadedCall) {
                cascadedCall = true;
            }
        } catch(Throwable ignored) {
//            ignored.printStackTrace();
        }
    }


    private void postProcessSecurityHook(byte[] dataBuffer, boolean currentCascadedCall, int offset, int readDataLength) {
        try {
            if(Boolean.FALSE.equals(inputStreamDataGatheringAllowed) ||
                    !NewRelicSecurity.isHookProcessingActive()) {
                return;
            }
//                System.out.println("Done IS2 "+ this.hashCode());
            if (Boolean.TRUE.equals(inputStreamDataGatheringAllowed) && !currentCascadedCall && readDataLength > -1) {
                char[] data = new char[readDataLength];
                for (int i = offset, y = 0; i < readDataLength; i++, y++) {
                    data[y] = (char) dataBuffer[i];
                }
                //                            System.out.println("Writing from IS 2" + this.hashCode() + " : " + String.valueOf(data));
                NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().getBody().append(data);

            }
//                System.out.println("Done out IS2 "+ this.hashCode());
        } catch (Throwable ignored) {
//                ignored.printStackTrace();
        }
    }

}
