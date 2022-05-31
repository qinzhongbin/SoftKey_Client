package com.qasky.softkey_client.util;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class UKeyContentSigner implements ContentSigner {
    private AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);
    private ByteArrayOutputStream stream = new ByteArrayOutputStream();

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return stream;
    }

    @Override
    public byte[] getSignature() {
        byte[] bytes = stream.toByteArray();
        //签名bytes, 给sign
        byte[] sign = null;
        return sign;
    }
}
