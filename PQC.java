package com.example.hexana;


/*
 * This class is an example of post-quantum hybrid encryption
 * 
 * */
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class PQC {

    private static final String PQKEM_ALGORITHM = "Kyber";
    private static final String PROVIDER = "BCPQC";
    private static final AlgorithmParameterSpec PQKEM_PARAMETER_SPEC = KyberParameterSpec.kyber768;
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String MODE_PADDING = "AES/ECB/PKCS5Padding";



    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        // the Bouncy Castle post quantum provider for the PQC KEM.
        Security.addProvider(new BouncyCastlePQCProvider());

        // Generating a key pair for receiver
        KeyPair keyPair = generateKeyPair();

        System.out.println("Post Quantum KEM Algorithm: " + keyPair.getPublic().getAlgorithm());
        System.out.println("Public Key length: " + keyPair.getPublic().getEncoded().length);
        System.out.println("Private Key length: " + keyPair.getPrivate().getEncoded().length);

        SecretKeyWithEncapsulation initKeyWithEnc = generateSecretKeySender(keyPair.getPublic());
        byte[] encapsulation = initKeyWithEnc.getEncapsulation();

        System.out.println("Shared Secret : " + Hex.toHexString(initKeyWithEnc.getEncoded()));
        System.out.println("Length of encapsulated shared secret: " + encapsulation.length);

        String originalText = "This is the message to send.";
        System.out.println("Original Text: " + originalText);

        String encryptedText = encrypt(originalText, initKeyWithEnc.getEncoded());
        System.out.println("Encrypted Text: " + encryptedText);


        SecretKeyWithEncapsulation recKeyWithEnc = generateSecretKeyReciever(keyPair.getPrivate(), encapsulation);

        System.out.println("Shared Secret decapsulated by Receiver: " + Hex.toHexString(recKeyWithEnc.getEncoded()));

        String decryptedText = decrypt(encryptedText, recKeyWithEnc.getEncoded());
        System.out.println("Decrypted Text: " + decryptedText);
    }
    
    public static String encrypt(String plainText, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, byte[] key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(MODE_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(PQKEM_ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(PQKEM_PARAMETER_SPEC, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKeyWithEncapsulation generateSecretKeySender(PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

   
        KeyGenerator keyGenerator = KeyGenerator.getInstance(PQKEM_ALGORITHM, PROVIDER);
        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, "Secret");
        keyGenerator.init(kemGenerateSpec);
        return  (SecretKeyWithEncapsulation)keyGenerator.generateKey();
    }

    private static SecretKeyWithEncapsulation generateSecretKeyReciever(PrivateKey privateKey, byte[] encapsulation)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, "Secret");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(PQKEM_ALGORITHM, PROVIDER);
        keyGenerator.init(kemExtractSpec);

        return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
    }
}