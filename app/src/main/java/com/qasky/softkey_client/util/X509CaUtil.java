package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 * 用于创建签名证书
 *
 * @author Zhu Jinping
 */
public class X509CaUtil {

    public static final String PROVIDER = "BC";

    private X509CaUtil() {
    }

    public static final int HOURS_IN_DAY = 24;
    private static long serialNumberBase = System.currentTimeMillis();

    /**
     * Calculate a serial number using a monotonically increasing value.
     *
     * @return a BigInteger representing the next serial number in the sequence.
     */
    public static synchronized BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }


    /**
     * Create a general end-entity certificate for use in verifying digital
     * signatures.
     *
     * @param signerCert certificate carrying the public key that will later
     *                   be used to verify this certificate's signature.
     * @param signerKey  private key used to generate the signature in the
     *                   certificate.
     * @param sigAlg     the signature algorithm to sign the certificate with.
     * @param certKey    public key to be installed in the certificate.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createEndEntity(X509CertificateHolder signerCert, PrivateKey signerKey, String sigAlg, PublicKey certKey, X500Name subject, int days, String crlDistPoint)
            throws CertIOException, GeneralSecurityException, OperatorCreationException {
        return createEndEntity(signerCert, signerKey, sigAlg, certKey, subject, days, crlDistPoint, null);
    }

    /**
     * Create a general end-entity certificate for use in verifying digital
     * signatures.
     *
     * @param signerCert certificate carrying the public key that will later
     *                   be used to verify this certificate's signature.
     * @param signerKey  private key used to generate the signature in the
     *                   certificate.
     * @param sigAlg     the signature algorithm to sign the certificate with.
     * @param certKey    public key to be installed in the certificate.
     * @param dnsName    website domain name for signing web service certificate
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createEndEntity(X509CertificateHolder signerCert, PrivateKey signerKey, String sigAlg, PublicKey certKey, X500Name subject, int days, String crlDistPoint, String dnsName)
            throws CertIOException, GeneralSecurityException, OperatorCreationException {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                DatetimeUtil.calculateDate(0),
                DatetimeUtil.calculateDate(HOURS_IN_DAY * days),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        CRLDistPointBuilder crlDistPointBuilder = new CRLDistPointBuilder();
        crlDistPointBuilder.addDistPoint(crlDistPoint);
        BasicConstraintsBuilder basicConstraintsBuilder = new BasicConstraintsBuilder();
        KeyUsageBuilder keyUsageBuilder = new KeyUsageBuilder();
        keyUsageBuilder.enableDefaultEndUserKeyUsage();
        builder.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        false, basicConstraintsBuilder.build())
                .addExtension(Extension.keyUsage,
                        true, keyUsageBuilder.build())
                .addExtension(Extension.cRLDistributionPoints, false, crlDistPointBuilder.build());

        if (!StringUtil.isEmpty(dnsName)) {
            GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
            generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, new DERIA5String(dnsName)));
            builder.addExtension(Extension.subjectAlternativeName, false, generalNamesBuilder.build());
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(PROVIDER).build(signerKey);

        return builder.build(signer);
    }

    /**
     * 生成自签名X509证书
     *
     * @param keyPair      密钥对，用于生成证书
     * @param userDN       证书的subject
     * @param sigAlg       签名算法标识
     * @param notBefore    有效期开始
     * @param notAfter     有效期结束
     * @param crlDistPoint CRL分发点
     * @return 自签名证书
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     */
    public static X509CertificateHolder genX509Certificate(KeyPair keyPair, String userDN, String sigAlg,
                                                           Date notBefore, Date notAfter, String crlDistPoint) throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        X500Name issuer = new X500Name(userDN);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                calculateSerialNumber(),
                notBefore,
                notAfter,
                issuer,
                keyPair.getPublic());
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        KeyUsageBuilder keyUsageBuilder = new KeyUsageBuilder();
        keyUsageBuilder.enableDefaultCaKeyUsage();

        builder.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(true))
                .addExtension(Extension.keyUsage,
                        true, keyUsageBuilder.build());

        if (!StringUtil.isEmpty(crlDistPoint)) {
            CRLDistPointBuilder crlDistPointBuilder = new CRLDistPointBuilder();
            crlDistPointBuilder.addDistPoint(crlDistPoint);
            builder.addExtension(Extension.cRLDistributionPoints, false, crlDistPointBuilder.build());
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(PROVIDER).build(keyPair.getPrivate());

        return builder.build(signer);
    }
}
