package codebase;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by micha on 11/14/2015.
 */
public class Encryption {


    public static SecretKey generateKey(byte[] sharedSecret) {
        MessageDigest md;
        SecretKey aesKey = null;
        try {
            md = MessageDigest.getInstance("SHA-256");

            byte[] hashSharedKey = md.digest(sharedSecret);

            //http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
            //It turns out that the Cipher class will generally not allow encryption with a key size of more than 128 bits
            byte[] AES128key = new byte[hashSharedKey.length / 2]; //we need 128 bit but we have 256 bits

            for (int i = 0; i < AES128key.length; i++) {
                //http://stackoverflow.com/questions/22410602/turn-string-to-128-bit-key-for-aes
                AES128key[i] = (byte) (hashSharedKey[i] ^ hashSharedKey[i + AES128key.length]); //XOR therefore we use all of them
            }

            aesKey = new SecretKeySpec(AES128key, "AES");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return aesKey;

    }




    public static OutputStream encrypt(String fileLocation, SecretKey key) {
        Cipher cipher;
        OutputStream outputStream = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            outputStream = new CipherOutputStream(new FileOutputStream(fileLocation), cipher);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return outputStream;

    }

    public static InputStream decrypt(String fileLocation, SecretKey key) {
        Cipher cipher;
        InputStream inputStream = null;
        try {

            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            inputStream = new CipherInputStream(new FileInputStream(fileLocation), cipher);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {

            System.err.println("Chatlog file could not be opened.");

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return inputStream;

    }

    private static byte[] getIV(byte[] secretKey) {
        MessageDigest md = null;
        byte[] iv = null;
        try {
            md = MessageDigest.getInstance("SHA1");
            iv = md.digest(secretKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return iv;

    }

    public static byte[] generateNonce() {
        //https://www.cigital.com/blog/proper-use-of-javas-securerandom/
        //SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        //http://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html#getInstanceStrong--
        //SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);

        return bytes;


    }

    public static byte[] generateHash(byte[] clientNonce, byte[] serverNonce,String password)
    {
        try {
            byte[] passwordByte = password.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            //http://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(clientNonce);
            outputStream.write(serverNonce);
            outputStream.write(passwordByte);

            byte[] toHash = outputStream.toByteArray();


            return md.digest(toHash);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


}
