package com.qasky.softkey_client.okhttp;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;

public class OkHttpUtil {
    private static OkHttpClient instance;

    public static OkHttpClient getInstance() {
        if (instance == null) {
            TrustAllManager trustAllManager = new TrustAllManager();
            SSLContext sc = null;
            try {
                sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[]{trustAllManager}, new SecureRandom());
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
            }

            instance = new OkHttpClient.Builder()
//                    .addInterceptor(chain -> chain.proceed(chain.request().newBuilder().addHeader("token", SPUtils.getInstance().getString("token")).addHeader("cookie", SPUtils.getInstance().getString("cookie")).build()))
                    .addInterceptor(new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY))
                    .sslSocketFactory(Objects.requireNonNull(sc).getSocketFactory(), trustAllManager)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
        }
        return instance;
    }
}
