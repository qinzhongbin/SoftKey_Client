//package com.qasky.softkey_client;
//
//import android.content.ComponentName;
//import android.content.Context;
//import android.content.Intent;
//import android.content.ServiceConnection;
//import android.os.IBinder;
//
//import com.qasky.softkey_server.ISKService;
//
//public class SoftKeyClient {
//    private SoftKeyClient() {
//    }
//
//    private static final SoftKeyClient instance = new SoftKeyClient();
//
//    public static SoftKeyClient getInstance() {
//        return instance;
//    }
//
//    private ISKService mService;
//
//    public ISKService getService() {
//        return mService;
//    }
//
//
//
//    public ISKService bindService(Context context, ServiceConnection connection) {
//
//
//        boolean success =
//        if (success) {
//            try {
//                Thread.sleep(200);
//                return mService;
//            } catch (InterruptedException e) {
//                e.printStackTrace();
//            }
//        }
//        return null;
//    }
//
//    public void unbindService(Context context) {
//        context.unbindService(mConnection);
//    }
//}
