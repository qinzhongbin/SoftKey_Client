/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SM4加解密
 *
 * @author Zhu Jinping
 */
public class Sm4Util {

    private static final String SM_4_CBC_PKCS_5_PADDING = "SM4/CBC/PKCS5Padding";
    private static final String SM_4 = "SM4";
    private static byte[] IV = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * SM4加密
     *
     * @param password 加密密码
     * @param plain    待加密内容
     * @return 已加密内容
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] encrypt(byte[] password, byte[] plain) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher instance = Cipher.getInstance(SM_4_CBC_PKCS_5_PADDING);
        SecretKey key = new SecretKeySpec(password, SM_4);
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(IV);
        instance.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec);
        return instance.doFinal(plain);
    }

    /**
     * SM4解密
     *
     * @param password  解密密码
     * @param encrypted 待解密内容
     * @return 已解密内容
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] decrypt(byte[] password, byte[] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher instance = Cipher.getInstance(SM_4_CBC_PKCS_5_PADDING);
        SecretKey key = new SecretKeySpec(password, "SM4");
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(IV);
        instance.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec);
        return instance.doFinal(encrypted);
    }
}
