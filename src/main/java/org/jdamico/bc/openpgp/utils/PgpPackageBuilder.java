package org.jdamico.bc.openpgp.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Created by apavlov on 16.07.18.
 */
public class PgpPackageBuilder {
    private static int INT_BUFFER_SIZE = 1024;
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    private PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
    PGPCompressedDataGenerator comData;
    OutputStream outputStream;
    private int rawBytes = 0;

    public PgpPackageBuilder(String name, Date dt) throws IOException {
        bOut = new ByteArrayOutputStream();
        lData = new PGPLiteralDataGenerator();
        comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        outputStream = lData.open(comData.open(bOut), PGPLiteralData.BINARY, name!=null?name:"data", dt!=null?dt:new Date(), new byte[INT_BUFFER_SIZE]);
    }

    public void write(byte data[], int offset, int len) throws IOException {
        outputStream.write(data, offset, len);
        rawBytes += len;
    }

    public int getBytes() {
        return bOut.size();
    }

    public int getRawBytes() {
        return rawBytes;
    }

    public byte[] flushPacket() throws IOException {
        outputStream.close();
        comData.close();
        return bOut.toByteArray();
    }
}
