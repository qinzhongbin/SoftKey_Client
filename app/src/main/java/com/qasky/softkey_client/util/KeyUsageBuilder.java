/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * 证书用途项构造器
 *
 * @author Zhu Jinping
 */
public class KeyUsageBuilder {
    private int keyUsage = 0;

    /**
     * 开启默认CA证书选项
     */
    public void enableDefaultCaKeyUsage() {
        this.keyUsage = KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyCertSign | KeyUsage.cRLSign;
    }

    /**
     * 开启默认用户证书选项
     */
    public void enableDefaultEndUserKeyUsage() {
        this.keyUsage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement;
    }

    /**
     * 构造证书用途项
     *
     * @return 证书用途项
     */
    public KeyUsage build() {
        return new KeyUsage(keyUsage);
    }
}
