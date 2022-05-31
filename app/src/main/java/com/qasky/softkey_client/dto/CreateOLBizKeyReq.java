package com.qasky.softkey_client.dto;

public class CreateOLBizKeyReq {

    private String secretSize;
    private String validityDate;
    private String systemId;
    private String serverId;
    private long timestamp;
    private String hmac;

    public String getSecretSize() {
        return secretSize;
    }

    public void setSecretSize(String secretSize) {
        this.secretSize = secretSize;
    }

    public String getValidityDate() {
        return validityDate;
    }

    public void setValidityDate(String validityDate) {
        this.validityDate = validityDate;
    }

    public String getSystemId() {
        return systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId;
    }

    public String getServerId() {
        return serverId;
    }

    public void setServerId(String serverId) {
        this.serverId = serverId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getHmac() {
        return hmac;
    }

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }
}
