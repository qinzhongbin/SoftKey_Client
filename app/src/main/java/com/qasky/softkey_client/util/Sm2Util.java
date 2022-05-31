/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * SM2算法工具类
 *
 * @author Zhu Jinping
 */
public class Sm2Util {
    static {
        Provider bc = Security.getProvider("BC");
        if (null == bc) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 安全程序提供者名称
     */
    private static final String PROVIDER = "BC";
    /**
     * 非对称加密算法名称
     */
    private static final String ALGORITHM = "EC";
    /**
     * SM2曲线名
     */
    private static final String SM2_CURVES_NAME = "sm2p256v1";
    /**
     * SM2参数
     */
    private static final X9ECParameters x9ECParameters = GMNamedCurves.getByName(SM2_CURVES_NAME);
    /**
     * 椭圆曲线域参数
     */
    private static final ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
    public static final String SM3_ALGORITHM = "SM3";
    public static final String DEFAULT_USER_ID = "1234567812345678";
    public static final String SIGNATURE_ALGORITHM = "SHA256WithSM2";

    /**
     * 载入私钥
     *
     * @param content 字节流
     * @return 私钥
     * @throws NoSuchAlgorithmException 算法标识不正确
     * @throws InvalidKeySpecException  有密码加密
     */
    public static PrivateKey loadPrivateKeyFromPKCS8(byte[] content) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(content);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
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
    public static PublicKey loadPublicKey(byte[] x509EncodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
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
    public static PrivateKey loadPrivateKeyFromPKCS8(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PemObject pemObject = PemUtil.loadPemFile(fileName);
        return loadPrivateKeyFromPKCS8(pemObject.getContent());
    }

    /**
     * 从Base64字符串中载入私钥
     *
     * @param base64Str Base64字符串
     * @return 私钥
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKeyFromPKCS8Base64String(String base64Str) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PemObject pemObject = PemUtil.loadPem(Base64.getDecoder().decode(base64Str));
        return loadPrivateKeyFromPKCS8(pemObject.getContent());
    }

    public static void save2Pkcs8(KeyPair keyPair){
//        PKCS8EncryptedPrivateKeyInfoBuilder pkcs8EncryptedPrivateKeyInfoBuilder = new PKCS8EncryptedPrivateKeyInfoBuilder();
//        pkcs8EncryptedPrivateKeyInfoBuilder.build();
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
    public static PublicKey loadPublicKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PemObject pemObject = PemUtil.loadPemFile(fileName);
        return loadPublicKey(pemObject.getContent());
    }

    /**
     * 生成SM2密钥对
     *
     * @return 密钥对
     * @throws Exception
     */
    public static KeyPair genKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        g.initialize(new ECNamedCurveGenParameterSpec(SM2_CURVES_NAME));
        return g.generateKeyPair();
    }

    /**
     * 使用SM2公钥加密数据
     *
     * @param pubKey  SM2公钥
     * @param srcData 待加密数据
     * @return 已加密数据
     * @throws InvalidCipherTextException 密钥不正确
     */
    public static byte[] encrypt(PublicKey pubKey, byte[] srcData)
            throws InvalidCipherTextException {
        if (!(pubKey instanceof BCECPublicKey)) {
            throw new InvalidCipherTextException("Wrong type of Public Key, BCECPublicKey is needed!");
        }
        BCECPublicKey bcecPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);
        SM2Engine engine = new SM2Engine();

        ParametersWithRandom pwr = new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom());
        engine.init(true, pwr);
        return engine.processBlock(srcData, 0, srcData.length);
    }


    /**
     * 使用私钥解密数据
     *
     * @param priKey    用于解密的私钥
     * @param encrypted 被对应公钥加密的密文
     * @return 解密后的数据
     * @throws InvalidCipherTextException 密钥不正确
     */
    public static byte[] decrypt(PrivateKey priKey, byte[] encrypted)
            throws InvalidCipherTextException {
        if (!(priKey instanceof BCECPrivateKey)) {
            throw new InvalidCipherTextException("Wrong type of private Key, BCECPrivateKey is required!");
        }

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) priKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), ecDomainParameters);
        SM2Engine engine = new SM2Engine();
        engine.init(false, ecPrivateKeyParameters);
        return engine.processBlock(encrypted, 0, encrypted.length);
    }

    public static byte[] sign(PrivateKey priKey, byte[] withId, byte[] srcData) throws CryptoException {
        if (!(priKey instanceof BCECPrivateKey)) {
            throw new InvalidCipherTextException("Wrong type of private Key, BCECPrivateKey is needed!");
        }
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) priKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(), ecDomainParameters);

        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        ParametersWithRandom pwr = new ParametersWithRandom(ecPrivateKeyParameters, new SecureRandom());
        if (withId != null) {
            param = new ParametersWithID(pwr, withId);
        } else {
            param = pwr;
        }
        signer.init(true, param);
        signer.update(srcData, 0, srcData.length);
        return signer.generateSignature();
    }

    public static boolean verify(PublicKey pubKey, byte[] withId, byte[] srcData, byte[] sign) throws InvalidCipherTextException {
        if (!(pubKey instanceof BCECPublicKey)) {
            throw new InvalidCipherTextException("Wrong type of Public Key, BCECPublicKey is needed!");
        }
        BCECPublicKey bcecPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);

        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (withId != null) {
            param = new ParametersWithID(ecPublicKeyParameters, withId);
        } else {
            param = ecPublicKeyParameters;
        }
        signer.init(false, param);
        signer.update(srcData, 0, srcData.length);
        return signer.verifySignature(sign);
    }


    /**
     * 计算SM3摘要
     *
     * @param raw 待计算数据
     * @return 摘要信息
     */
    public static byte[] sm3ForSignature(PublicKey publicKey, byte[] raw) throws NoSuchAlgorithmException {
        if (!(publicKey instanceof BCECPublicKey)) {
            throw new NoSuchAlgorithmException("Wrong type of Public Key, BCECPublicKey is needed!");
        }
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECPoint ecPoint = bcecPublicKey.getQ();
        byte[] z = getZ(ecPoint, DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8));
        MessageDigest digest = MessageDigest.getInstance(SM3_ALGORITHM);
        digest.reset();
        digest.update(z);
        digest.update(raw);
        return digest.digest();
    }

    public static byte[] getZ(ECPoint ecPoint, byte[] userID) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(SM3_ALGORITHM);
        digest.reset();

        addUserID(digest, userID);

        addFieldElement(digest, ecDomainParameters.getCurve().getA());
        addFieldElement(digest, ecDomainParameters.getCurve().getB());
        addFieldElement(digest, ecDomainParameters.getG().getAffineXCoord());
        addFieldElement(digest, ecDomainParameters.getG().getAffineYCoord());
        addFieldElement(digest, ecPoint.getAffineXCoord());
        addFieldElement(digest, ecPoint.getAffineYCoord());

        return digest.digest();
    }

    private static void addUserID(MessageDigest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private static void addFieldElement(MessageDigest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }
}
