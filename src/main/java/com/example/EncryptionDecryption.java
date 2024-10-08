package com.example;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


public class EncryptionDecryption {

    private static final int iterations = 65536;
    private static final int keySize = 256;
    private static byte[] ivBytes;

    public static void main(String[] args) throws Exception {
        String message = "PasswordToEncrypt";
        String encrypted = encrypt(message);
        String decrypted = decrypt(encrypted);

        System.out.println("Message: " + message);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    public static String encrypt(String plaintext) throws Exception {
        String salt = getSalt();
        byte[] saltBytes = Base64.getDecoder().decode(salt);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(plaintext.toCharArray(), saltBytes, iterations, keySize);
        SecretKeySpec secretSpec = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(encryptedTextBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        byte[] saltBytes = Base64.getDecoder().decode(getSalt());
        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(encryptedText.toCharArray(), saltBytes, iterations, keySize);
        SecretKeySpec secretSpec = new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretSpec, new IvParameterSpec(ivBytes));
        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);

        return new String(decryptedTextBytes);
    }

    public static String getSalt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
