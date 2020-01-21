package com.k2cybersecurity.instrumentator.decorators.servletreader;

import com.k2cybersecurity.instrumentator.custom.ThreadLocalHTTPIOLock;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalHttpMap;
import com.k2cybersecurity.instrumentator.custom.ThreadLocalOperationLock;

import java.nio.CharBuffer;

public class Callbacks {

    public static final String READ = "read";
    public static final String READ_LINE = "readLine";

    public static void doOnEnter(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 String exectionId) {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired() && obj != null && ThreadLocalHttpMap.getInstance().getRequestReader() != null && ThreadLocalHttpMap.getInstance().getRequestReader().hashCode() == obj.hashCode()
                && !ThreadLocalHTTPIOLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//						System.out.println("OnStart :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//								+ " - return : " + returnVal + " - eid : " + exectionId);
                ThreadLocalHTTPIOLock.getInstance().acquire(obj);
            } finally {
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnExit(String sourceString, String className, String methodName, Object obj, Object[] args,
                                Object returnVal, String exectionId) {

        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired() && obj != null && ThreadLocalHttpMap.getInstance().getRequestReader() != null && ThreadLocalHttpMap.getInstance().getRequestReader().hashCode() == obj.hashCode()
                && ThreadLocalHTTPIOLock.getInstance().isAcquired(obj)) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();

                switch (methodName) {
                case READ:
                        if(args != null && args.length == 1 && args[0] instanceof char[] && (int)returnVal != -1){
                            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(String.valueOf((char[]) args[0], 0, (int)returnVal).getBytes());
                        } else if(args != null && args.length == 1 && args[0] instanceof CharBuffer && (int)returnVal != -1){
                            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(String.valueOf(((CharBuffer) args[0]).array(), 0, (int)returnVal).getBytes());
                        }else if (args != null && args.length == 3 && args[0] instanceof char[] && (int)returnVal != -1) {
                            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(String.valueOf((char[]) args[0], (int) args[1], (int)returnVal).getBytes());
                        } else if (returnVal instanceof Integer) {
                            int readByte = (int) returnVal;
                            if (readByte != -1) {
                                ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(new Integer(readByte).byteValue());
                            }
                        }
                        //                        System.out.println("Inserting to request via reader : " + args[0] + " :: " + obj.hashCode());
                        break;
                case READ_LINE:
                        if (returnVal != null) {
                            ThreadLocalHttpMap.getInstance().insertToRequestByteBuffer(((String) returnVal).getBytes());
                        }
                        //                        System.out.println("Inserting to request via reader : " + args[0] + " :: " + obj.hashCode());
                        break;
                }

            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }

    public static void doOnError(String sourceString, String className, String methodName, Object obj, Object[] args,
                                 Throwable error, String exectionId) throws Throwable {
        if (!ThreadLocalHttpMap.getInstance().isEmpty() && !ThreadLocalOperationLock.getInstance().isAcquired()) {
            try {
                ThreadLocalOperationLock.getInstance().acquire();
//                System.out.println("OnError :" + sourceString + " - args : " + Arrays.asList(args) + " - this : " + obj
//                        + " - error : " + error + " - eid : " + exectionId);
            } finally {
                ThreadLocalHTTPIOLock.getInstance().release(obj);
                ThreadLocalOperationLock.getInstance().release();
            }
        }
    }
}
