package org.jdamico.bc.openpgp.tests;


import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.jdamico.bc.openpgp.utils.PgpDecryptedStream;
import org.jdamico.bc.openpgp.utils.PgpPackageBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.*;
import java.util.Arrays;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.jdamico.bc.openpgp.utils.PgpHelper;
import org.jdamico.bc.openpgp.utils.RSAKeyPairGenerator;

import static org.junit.Assert.*;


public class TestBCOpenPGP {

    private static boolean isArmored = true;
    private static String id = "damico";
    private static String passwd = "******";
    private static boolean integrityCheck = true;


    private static String pubKeyFile = "test_out/pub.asc";
    private static String privKeyFile = "test_out/secret.asc";

    private static String plainTextFile = "test_out/plain-text.txt";
    private static String cipherTextFile = "test_out/cypher-text.asc";
    private static String decPlainTextFile = "test_out/dec-plain-text.txt";
    private static String signatureFile = "test_out/signature.txt";

    @BeforeClass
    public static void setUp() throws Exception {
        if (Files.notExists(Paths.get("test_out"))) {
            Files.createDirectory(Paths.get("test_out"));
        }

        if (Files.notExists(Paths.get(plainTextFile))) {
            byte[] rand = new byte[819200];
            new SecureRandom().nextBytes(rand);
            Files.write(Paths.get(plainTextFile), Base64.getEncoder().encode(rand));
        }
    }

    @BeforeClass
    public static void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {
        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair kp = kpg.generateKeyPair();

        FileOutputStream out1 = new FileOutputStream(privKeyFile);
        FileOutputStream out2 = new FileOutputStream(pubKeyFile);

        rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
        out1.close();
        out2.close();
    }

    @Test
    public void encrypt() throws NoSuchProviderException, IOException, PGPException {
        long start = System.currentTimeMillis();

        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();

        System.out.println("encrypt() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        byte[] orgF = Files.readAllBytes(Paths.get(plainTextFile));
        byte[] newF = Files.readAllBytes(Paths.get(cipherTextFile));

        assertNotEquals(Arrays.toString(orgF), Arrays.toString(newF));
    }

    @Test
    public void decrypt() throws Exception {
        long start = System.currentTimeMillis();

        FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();

        System.out.println("decrypt() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        byte[] orgF = Files.readAllBytes(Paths.get(plainTextFile));
        byte[] newF = Files.readAllBytes(Paths.get(decPlainTextFile));

        assertArrayEquals(orgF, newF);
    }

    @Test
    public void testDecryptOnStream() throws Exception {
        byte[] orgF = Files.readAllBytes(Paths.get(plainTextFile));

        PgpDecryptedStream decryptedIn = new PgpDecryptedStream(new FileInputStream(cipherTextFile), new FileInputStream(privKeyFile), passwd.toCharArray());
        InputStream plainIn = new FileInputStream(plainTextFile);

        int num1 = 0;
        int num2 = 0;
        int total = 0;

        while(num1 > -1 && num2 > -1) {
            num1 = plainIn.read();
            num2 = decryptedIn.read();
            assertEquals(num1, num2);
            ++total;
        }

        assertEquals(orgF.length, total - 1);
        plainIn.close();
        decryptedIn.close();
    }

    @Test
    public void signAndVerify() throws Exception {
        long start = System.currentTimeMillis();

        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileInputStream plainTextInput = new FileInputStream(plainTextFile);
        FileOutputStream signatureOut = new FileOutputStream(signatureFile);

        // todo: remove that?
        // byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);

        byte[] sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);

        boolean res = PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs);

        System.out.println("signAndVerify() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        assertTrue(res);
    }


    @Test
    public void testInputStreamEncryption() throws Exception {
        byte bytes[] = new byte[1000];

        for (int i = 0; i < bytes.length; ++i) bytes[i] = (byte) (0x30 + i / 100);

        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        PgpHelper.getInstance().encryptInputStream(outputStream
                , new ByteArrayInputStream(bytes)
                , PgpHelper.getInstance().readPublicKey(pubKeyIs)
                , isArmored
                , integrityCheck
                , null
                , null);

        outputStream.flush();
        byte bytesOut[] = outputStream.toByteArray();
        outputStream.close();

        ByteArrayOutputStream plainOutput = new ByteArrayOutputStream();
        ByteArrayInputStream chIn = new ByteArrayInputStream(bytesOut);

        PgpHelper.getInstance().decryptFile(chIn
                , plainOutput
                , new FileInputStream(privKeyFile)
                , passwd.toCharArray());

        byte[] plainRes = plainOutput.toByteArray();
        assertEquals(bytes.length, plainRes.length);
        assertArrayEquals(bytes, plainRes);
    }

    @Test
    public void testPacketBuilder() throws Exception {
        PGPPublicKey encKey = PgpHelper.getInstance().readPublicKey(new FileInputStream(pubKeyFile));
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom()));

        // prepare input data
        byte bytes[] = new byte[10000];
        for (int i = 0; i < bytes.length; ++i) bytes[i] = (byte) (0x30 + i / 100);

        PgpPackageBuilder pgpPkg = new PgpPackageBuilder("xxx", null);
        pgpPkg.write(bytes, 0, 1000);
        pgpPkg.write(bytes, 1000, 8999);
        pgpPkg.write(bytes, 9999, 1);
        assertEquals(10000, pgpPkg.getRawBytes());

        byte[] packetBytes = pgpPkg.flushPacket();
        assertTrue(packetBytes.length > 0);

        ByteArrayOutputStream encrStream = new ByteArrayOutputStream();

        {
            OutputStream cOut = cPk.open(encrStream, packetBytes.length);
            cOut.write(packetBytes);
            cOut.close();
        }

        ByteArrayInputStream chIn = new ByteArrayInputStream(encrStream.toByteArray());
        ByteArrayOutputStream plainOutput = new ByteArrayOutputStream();

        PgpHelper.getInstance().decryptFile(chIn
                , plainOutput
                , new FileInputStream(privKeyFile)
                , passwd.toCharArray());

        byte[] plainRes = plainOutput.toByteArray();
        assertEquals(bytes.length, plainRes.length);
        assertArrayEquals(bytes, plainRes);
    }
}