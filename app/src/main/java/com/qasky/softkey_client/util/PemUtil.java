/*
 * Copyright (c) 2020. Qasky. All rights reserved.
 */

package com.qasky.softkey_client.util;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

/**
 * PEM工具类
 * @author Zhu Jinping
 */
public class PemUtil {

    /**
     * 载入PEM文件
     *
     * @param fileName 文件位置
     * @return PEM对象
     * @throws IOException 读取异常
     */
    public static PemObject loadPemFile(String fileName) throws IOException {
        try (PemReader reader = new PemReader(new FileReader(fileName))) {
            return reader.readPemObject();
        }
    }


    /**
     * 载入PEM对象
     *
     * @param pemContent PEM内容
     * @return PEM对象
     * @throws IOException 读取异常
     */
    public static PemObject loadPem(byte[] pemContent) throws IOException {

        try (InputStream inputStream = new ByteArrayInputStream(pemContent);
             Reader reader = new InputStreamReader(inputStream);
             PemReader pemReader = new PemReader(reader)) {
            return pemReader.readPemObject();
        }
    }


    /**
     * Convert JCA Object to PEM string
     *
     * @param jcaObject type of X509Certificate X509CRL, KeyPair, PrivateKey, PublicKey
     * @return PEM string
     * @throws IOException IO异常
     */
    public static String convertJCAObject(Object jcaObject) throws IOException {
        try (Writer writer = new StringWriter(1);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {

            pemWriter.writeObject(jcaObject);
            pemWriter.flush();
            return writer.toString();
        }
    }

    /**
     * 转换证书对象到PEM字符串
     *
     * @param certificate 要转换的证书对象
     * @return PEM格式的字节数组
     * @throws IOException IO异常
     */
    public static byte[] convertJcaObject2PemArray(X509Certificate certificate) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             Writer writer = new OutputStreamWriter(byteArrayOutputStream, StandardCharsets.UTF_8);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {

            pemWriter.writeObject(certificate);
            pemWriter.flush();
            return byteArrayOutputStream.toByteArray();
        }
    }
}
