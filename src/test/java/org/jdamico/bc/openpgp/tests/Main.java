package org.jdamico.bc.openpgp.tests;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.jdamico.bc.openpgp.utils.PgpHelper;

import java.io.*;
import java.security.SecureRandom;

/**
 * Created by apavlov on 13.07.18.
 */
public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Please provide input file, key and output file");
        }

        FileInputStream cipheredFileIs = new FileInputStream(new File(args[0]));
        FileInputStream privKeyIn = new FileInputStream(new File(args[1]));
        FileOutputStream plainTextFileIs = new FileOutputStream(new File(args[2]));

        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, "reltio".toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }
}
