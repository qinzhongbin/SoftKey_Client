package com.qasky.softkey_server;

import com.qasky.softkey_server.qcard.Application;
import com.qasky.softkey_server.qcard.NegotiateInfo;

interface ISKService {

    int getPid();

    byte[] getPem();
    void setSessionKey(in byte[] key);

    boolean enumDev();
    void freeDevs();

    boolean loginDev();
    boolean logoutDev();

    boolean initResource();
    boolean updateResource();
    void destroyResource();

    String getDeviceId();
    String getSystemId(String appName, String conName);
    List<Application> getAppList();

    long[] queryKeyLength(String appName, String conName);
    boolean chargeKey(String host, String appName, String conName, String userPIN);

    long getKeyHandle(String appName, String conName, String userPIN, String checkCode, String flag);
    void freeKeyHandle(long keyHandle);

    byte[] encrypt(long keyHandle, in byte[] plain);
    byte[] decrypt(long keyHandle, in byte[] cipher);
    byte[] getSoftKey(long keyHandle, long keyLen);

    byte[] exportCert(int type, String appName, String conName);
    byte[] exportPubKey(int type, String appName, String conName);

    boolean verifyAppPIN(String appName, String PIN);

    NegotiateInfo negoOLBizKey(String host, String deviceId, String systemId, String secretId, String serverId, String visitKeyBase64, String protectKey);
}