/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA算法工具类
 *
 * @author Zhu Jinping
 */
public class RsaUtil {
    static {
        Provider bc = Security.getProvider("BC");
        if (null == bc) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 非对称加密算法名称
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 加解密算法
     */
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    public static final int RSA_KEY_SIZE = 2048;

    /**
     * 载入私钥
     *
     * @param content 字节流
     * @return 私钥
     * @throws NoSuchAlgorithmException 算法标识不正确
     * @throws InvalidKeySpecException  有密码加密
     */
    public static PrivateKey loadPrivateKeyFromPKCS8(byte[] content) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(content);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    /**
     * 从数组创建公钥
     *
     * @param x509EncodedPublicKey 数组
     * @return 公钥
     * @throws NoSuchAlgorithmException 非RSA公钥
     * @throws InvalidKeySpecException  有密码保护的公钥（不支持）
     */
    public static PublicKey loadPublicKey(byte[] x509EncodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(x509EncodedPublicKey);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    /**
     * 载入私钥
     *
     * @param fileName 文件位置
     * @return 私钥
     * @throws IOException              读取异常
     * @throws NoSuchAlgorithmException 算法标识不正确
     * @throws InvalidKeySpecException  有密码加密
     */
    public static PrivateKey loadPrivateKeyFromPKCS8(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemObject pemObject = PemUtil.loadPemFile(fileName);
        return loadPrivateKeyFromPKCS8(pemObject.getContent());
    }

    /**
     * 从文件载入公钥
     *
     * @param fileName 文件位置
     * @return 公钥
     * @throws IOException              读异常
     * @throws NoSuchAlgorithmException 非RSA公钥
     * @throws InvalidKeySpecException  有密码保护的公钥（不支持）
     */
    public static PublicKey loadPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemObject pemObject = PemUtil.loadPemFile(fileName);
        return loadPublicKey(pemObject.getContent());
    }

    /**
     * 生成RSA密钥对
     *
     * @return RSA密钥对
     * @throws Exception
     */
    public static KeyPair genKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(ALGORITHM);
        g.initialize(RSA_KEY_SIZE);
        return g.generateKeyPair();
    }

    /**
     * 使用RSA私钥加密数据
     *
     * @param privateKey RSA私钥
     * @param rawData    待加密数据
     * @return 加密后数据
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(PrivateKey privateKey, byte[] rawData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(rawData);
    }

    /**
     * 使用RSA公钥解密数据
     *
     * @param publicKey RSA公钥
     * @param rawData   待加密数据
     * @return 加密后数据
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] rawData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(rawData);
    }

    /**
     * 使用RSA私钥解密数据
     *
     * @param privateKey    RSA私钥
     * @param encryptedData 待解密数据
     * @return 解密后数据
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * 使用RSA公钥解密数据
     *
     * @param publicKey     RSA公钥
     * @param encryptedData 待解密数据
     * @return 解密后数据
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(PublicKey publicKey, byte[] encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * 使用私钥对数据进行签名
     *
     * @param privateKey 私钥
     * @param rawData    待签名数据
     * @return 签名数据
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(PrivateKey privateKey, byte[] rawData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(rawData);
        return signature.sign();

    }

    /**
     * 使用公钥对数据进行签名
     *
     * @param publicKey     公钥
     * @param rawData       待验证数据
     * @param signatureData 待验证签名数据
     * @return 验证结果 true 成功， false 失败
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(PublicKey publicKey, byte[] rawData, byte[] signatureData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(rawData);
        return signature.verify(signatureData);
    }
}
