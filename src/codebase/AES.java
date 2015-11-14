package codebase;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by micha on 11/14/2015.
 */
public class AES {

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

    public static byte[] encrypt(byte[] plaintext, SecretKey symmetricKeyAES) {
        //System.out.println("ciphermaxlength: "+ Cipher.getMaxAllowedKeyLength("AES/ECB/PKCS5Padding"));
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKeyAES);
            encrypted = cipher.doFinal(plaintext);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    public static ChatPacket decrypt(ByteArrayInputStream byteArrayInputStream, SecretKey symmetricKeyAES) {
        Cipher cipher;
        ChatPacket chatPacket = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKeyAES);
            CipherInputStream cis = new CipherInputStream(byteArrayInputStream, cipher);


            ObjectInput objectInput = new ObjectInputStream(cis);
            Object object = objectInput.readObject();
            chatPacket = (ChatPacket)object;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        return chatPacket;

    }

}
