/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * SM3摘要算法工具类
 *
 * @author Zhu Jinping
 */
public class Sm3Util {
    public static final String ALGORITHM = "SM3";

    static {
        if(null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)){
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    /**
     * 计算SM3摘要
     *
     * @param raw 待计算数据
     * @return 摘要信息
     */
    public static byte[] digest(byte[] raw) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(raw);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(ALGORITHM + " Digest algorithm is not supported!", e);
        }
    }
}
