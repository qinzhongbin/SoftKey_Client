package com.qasky.softkey_client;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import androidx.annotation.NonNull;

public class MessageHandler extends Handler {
    public MessageHandler(@NonNull Looper looper) {
        super(looper);
    }

    @Override
    public void handleMessage(@NonNull Message msg) {

        switch (msg.what) {
            case 0:
                Log.d("MessageHandler", "Client received hello");
                break;
            default:
                super.handleMessage(msg);
        }
    }



}



