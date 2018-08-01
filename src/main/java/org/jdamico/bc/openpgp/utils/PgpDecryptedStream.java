package org.jdamico.bc.openpgp.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

import static org.jdamico.bc.openpgp.utils.PgpHelper.findSecretKey;


/**
 * Created by apavlov on 01.08.18.
 */
public class PgpDecryptedStream extends InputStream {

    private InputStream decryptedIn;
    private PGPLiteralData ld;              // need literal data for continue reading
    private PGPPublicKeyEncryptedData pbe;  // for integrity checking

    public PgpDecryptedStream(InputStream in, InputStream keyIn, char[] passwd) throws IOException, NoSuchProviderException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }


        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();
            sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);

        InputStream clear = pbe.getDataStream(b);

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);

        Object message = plainFact.nextObject();

        if (message != null) {
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                ld = (PGPLiteralData) message;
                decryptedIn = ld.getInputStream();

            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }
        }
    }

    @Override
    public int read() throws IOException {
        return decryptedIn.read();
    }

    @Override
    public int read(byte b[]) throws IOException {
        return decryptedIn.read(b);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return decryptedIn.read(b, off, len);
    }

    @Override
    public void close() throws IOException {
        if (decryptedIn != null) decryptedIn.close();

        try {
            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    throw new PGPException("Message failed integrity check");
                }
            }
        } catch(PGPException e) {
            throw new IOException("Integrity check failed " + e.getMessage());
        }
    }
}
