package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * 证书工具类，提供证书相关的操作
 *
 * @author Zhu Jinping
 */
public class CertificateUtil {

    static {
        Provider bc = Security.getProvider("BC");
        if(null == bc){
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    private CertificateUtil() {
    }

    /**
     * 证书格式名称
     */
    private static final String TYPE = "X.509";
    /**
     * 安全程序提供者名称
     */
    private static final String PROVIDER = "BC";

    /**
     * 从文件载入证书
     *
     * @param certFileName 文件名
     * @return 证书对象
     * @throws IOException          文件不存在
     * @throws CertificateException 证书载入异常
     */
    public static X509Certificate loadX509Certificate(String certFileName) throws IOException, CertificateException {
        try (InputStream inStream = Files.newInputStream(Paths.get(certFileName))) {
            CertificateFactory factory = CertificateFactory.getInstance(TYPE, BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) factory.generateCertificate(inStream);
        } catch (NoSuchProviderException e) {
            throw new IOException(e);
        }
    }

    /**
     * 从字节流中载入证书
     *
     * @param certContent 证书内容字节流
     * @return 证书对象
     * @throws IOException          字节流异常
     * @throws CertificateException 字节流中的格式异常
     */
    public static X509Certificate loadX509Certificate(byte[] certContent) throws IOException, CertificateException {
        try (InputStream inStream = new ByteArrayInputStream(certContent)) {
            CertificateFactory factory = CertificateFactory.getInstance(TYPE, BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) factory.generateCertificate(inStream);
        } catch (NoSuchProviderException e) {
            throw new IOException(e);
        }
    }

    /**
     * 从base64编码的证书载入证书对象
     *
     * @param certString base64编码的证书
     * @return 证书对象
     * @throws CertificateException 证书载入异常
     */
    public static X509Certificate loadX509CertificateFromBase64String(String certString) throws CertificateException, IOException {
        return loadX509Certificate(Base64.getDecoder().decode(certString));
    }


    /**
     * 保存证书到文件
     *
     * @param fileName    文件位置
     * @param certificate 证书对象
     * @throws IOException 写出错误
     */
    public static void writeCertificatePEM(String fileName, Certificate certificate) throws IOException {
        try (Writer writer = new FileWriter(fileName);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
        }
    }

    /**
     * 从字节流转为CRL
     *
     * @param crlStream 包含CRL的字节流
     * @return X509CRL
     * @throws CRLException            CRL格式异常
     * @throws CertificateException    CRL格式异常
     * @throws NoSuchProviderException bouncycastle库异常
     */
    public static X509CRL loadX509CRL(byte[] crlStream) throws CRLException, CertificateException, NoSuchProviderException {
        CertificateFactory cFact = CertificateFactory.getInstance(TYPE, PROVIDER);
        return (X509CRL) cFact.generateCRL(new ByteArrayInputStream(crlStream));
    }

    /**
     * 转换证书文件DRR到PEM
     *
     * @param certificate
     * @return PEM字符串
     * @throws IOException IO异常
     */
    public static String convertCertificate2Pem(X509Certificate certificate) throws IOException {
        return PemUtil.convertJCAObject(certificate);
    }

    /**
     * 创建PKCS10
     *
     * @param publicKey  待生成的公钥
     * @param privateKey 待生成的私钥
     * @param sigAlg     算法标识
     * @param c          国家
     * @param st         省份
     * @param l          市
     * @param o          公司
     * @param o          部门
     * @param cn         通用名
     * @return PKCS10
     * @throws OperatorCreationException 参数有误
     */
    public static PKCS10CertificationRequest createPKCS10(PublicKey publicKey, PrivateKey privateKey, String sigAlg, String c, String st, String l, String o, String ou, String cn) throws OperatorCreationException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, c)
                .addRDN(BCStyle.ST, st)
                .addRDN(BCStyle.L, l)
                .addRDN(BCStyle.O, o)
                .addRDN(BCStyle.OU, ou)
                .addRDN(BCStyle.CN, cn);
        X500Name x500Name = x500NameBuilder.build();

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        PKCS10CertificationRequestBuilder requestBuilder = new PKCS10CertificationRequestBuilder(x500Name, publicKeyInfo);

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(PROVIDER).build(privateKey);
        return requestBuilder.build(signer);
    }

    /**
     * 从文件载入PKCS10
     *
     * @param fileName 文件位置
     * @return PKCS10
     * @throws IOException 读取错误
     */
    public static PKCS10CertificationRequest loadPKCS10(String fileName) throws IOException {
        PemObject pemObject = PemUtil.loadPemFile(fileName);
        if (null == pemObject) {
            throw new IOException("PEM Object is Null");
        }
        return new PKCS10CertificationRequest(pemObject.getContent());
    }

    /**
     * 从PEM数组中载入PKCS10
     *
     * @param content PEM内容
     * @return PKCS10对象
     * @throws IOException IO异常
     */
    public static PKCS10CertificationRequest loadPKCS10(byte[] content) throws IOException {
        PemObject pemObject = PemUtil.loadPem(content);
        if (null == pemObject) {
            throw new IOException("PEM Object is Null");
        }
        return new PKCS10CertificationRequest(pemObject.getContent());
    }


    /**
     * 转换X509CertificateHolder 到X509Certificate
     *
     * @param certHolder 转换X509CertificateHolder
     * @return X509Certificate
     * @throws GeneralSecurityException 转换异常
     * @throws IOException              转换异常
     */
    public static X509Certificate convertX509CertificateHolder(
            X509CertificateHolder certHolder)
            throws GeneralSecurityException, IOException {
        CertificateFactory cFact = CertificateFactory.getInstance(TYPE, PROVIDER);

        return (X509Certificate) cFact.generateCertificate(
                new ByteArrayInputStream(
                        certHolder.getEncoded()));
    }

    /**
     * 从SubjectPublicKeyInfo中获取公钥对象
     *
     * @param subjectPublicKeyInfo
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public static PublicKey loadPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException {
        AsymmetricKeyParameter
                asymmetricKeyParameter = PublicKeyFactory.createKey(subjectPublicKeyInfo);
        if (asymmetricKeyParameter instanceof RSAKeyParameters) {
            return RsaUtil.loadPublicKey(subjectPublicKeyInfo.getEncoded());
        } else if (asymmetricKeyParameter instanceof ECPublicKeyParameters) {
            return Sm2Util.loadPublicKey(subjectPublicKeyInfo.getEncoded());
        }
        throw new InvalidKeySpecException("Unknown type of public key");
    }

}
