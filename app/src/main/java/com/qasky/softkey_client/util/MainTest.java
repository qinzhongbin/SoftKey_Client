package com.qasky.softkey_client.util;

import org.bouncycastle.cert.X509CertificateHolder;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class MainTest {

    public static void main(String[] args) throws Exception {
//
//        System.out.println("-------------------------------RSA test for Create Keypair, create PKCS10(CSR), Sign data---------------------------");
//        KeyPair rsaKeyPair = RsaUtil.genKeyPair();
//        PKCS10CertificationRequest rsaPkcs10 = CertificateUtil.createPKCS10(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate(), RsaUtil.SIGNATURE_ALGORITHM, "CN", "Anhui", "Wuhu", "Qasky", "TestDept", "IkLH");
//        String rsaPem = PemUtil.convertJCAObject(rsaPkcs10);
//        System.out.println(rsaPem);
//        String rsaCSR = Base64.getEncoder().encodeToString(rsaPem.getBytes());
//        System.out.println(rsaCSR);
//
//        byte[] rsaSignature = RsaUtil.sign(rsaKeyPair.getPrivate(), "rawdata".getBytes());
//        System.out.println(rsaSignature.length);
//        System.out.println(Base64.getEncoder().encodeToString(rsaSignature));
//
//        System.out.println("-------------------------------SM2 test for Create Keypair, create PKCS10(CSR), Sign data---------------------------");
//        KeyPair sm2KeyPair = Sm2Util.genKeyPair();
//
//        PKCS10CertificationRequest sm2Pkcs10 = CertificateUtil.createPKCS10(sm2KeyPair.getPublic(), sm2KeyPair.getPrivate(), Sm2Util.SIGNATURE_ALGORITHM, "CN", "Anhui", "Wuhu", "Qasky", "TestDept", "IkLH");
//        String sm2Pem = PemUtil.convertJCAObject(sm2Pkcs10);
//        System.out.println(sm2Pem);
//        String sm2CSR = Base64.getEncoder().encodeToString(sm2Pem.getBytes());
//        System.out.println(sm2CSR);
//
//        byte[] sm2Signature = Sm2Util.sign(sm2KeyPair.getPrivate(), null, "rawdata".getBytes());
//        System.out.println(sm2Signature.length);
//        System.out.println(Base64.getEncoder().encodeToString(sm2Signature));
//
//        System.out.println("-------------------------------Symmetric Authentication response---------------------------");
//        String appName = "appName";
//        String containerName = "containerName";
//        String randomNumber = Base64.getEncoder().encodeToString(new byte[]{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f});
//        //以上三个参数是从服务器拿到的,客户端两种算法的加密/签名示例如下：
//        //deviceId,randomNumber, encrytedRandom这三个参数返回给服务端进行认证
//        byte[] sign = Sm2Util.sign(sm2KeyPair.getPrivate(), null, Base64.getDecoder().decode(randomNumber));
//        String encrytedRandom = Base64.getEncoder().encodeToString(sign);
//        System.out.println("Sm2 encrytedRandom:" + encrytedRandom);
//
//        sign = RsaUtil.sign(rsaKeyPair.getPrivate(), Base64.getDecoder().decode(randomNumber));
//        encrytedRandom = Base64.getEncoder().encodeToString(sign);
//        System.out.println("Rsa encrytedRandom:" + encrytedRandom);
//
//        System.out.println("-------------------------------SM3 Test---------------------------");
//        byte[] sm3hash = Sm3Util.digest("hello".getBytes());
//        System.out.println("sm3hash:" + BytesUtils.bytes2String(sm3hash));
//
//        System.out.println("-------------------------------SM4 Test---------------------------");
//        String password = "1234567812345678";
//        byte[] rawdata = "rawdata".getBytes();
//        byte[] sm4Encrypted = Sm4Util.encrypt(password.getBytes(), rawdata);
//        byte[] sm4Decrypted = Sm4Util.decrypt(password.getBytes(), sm4Encrypted);
//
//        System.out.println("rawdata:" + BytesUtils.bytes2String(rawdata));
//        System.out.println("sm4Encrypted:" + BytesUtils.bytes2String(sm4Encrypted));
//        System.out.println("sm4Decrypted:" + BytesUtils.bytes2String(sm4Decrypted));
//

        KeyPair keyPair = Sm2Util.genKeyPair();
        X509CertificateHolder x509CertificateHolder = X509CaUtil.genX509Certificate(keyPair, "CN = SoftkeyId,O = Qasky,C = CN", "SM3WITHSM2", Calendar.getInstance().getTime(), Calendar.getInstance().getTime(), "https://crl.qasky.com/crl");

        CertificateUtil.writeCertificatePEM("e:\\test11111.cer", CertificateUtil.convertX509CertificateHolder(x509CertificateHolder));
        byte[] encoded = x509CertificateHolder.getEncoded();
        X509Certificate certificate = CertificateUtil.loadX509Certificate(encoded);
        byte[] encrypt = Sm2Util.encrypt(certificate.getPublicKey(), "a".getBytes());
        byte[] decrypt = Sm2Util.decrypt(keyPair.getPrivate(), encrypt);
        System.out.println(BytesUtils.bytes2String(encrypt));
        System.out.println(BytesUtils.bytes2String(decrypt));

    }

}
