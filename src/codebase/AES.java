package codebase;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by micha on 11/14/2015.
 */
public class AES {

    public enum mode {
        ENCRYPT,
        DECRYPT
    }

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
            chatPacket = (ChatPacket) object;

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

    public static InputStream securedFile(mode mode, String fileName, SecretKey key) {


        Cipher cipher;
        InputStream inputStream = null;
        byte[] output = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            switch (mode) {
                case ENCRYPT:
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    // OutputStream out = new FileOutputStream(this.getChatLogPath());
                    break;
                case DECRYPT:
                    cipher.init(Cipher.DECRYPT_MODE, key);
                    inputStream = new CipherInputStream(new FileInputStream(fileName), cipher);
                    break;
            }

            inputStream = new CipherInputStream(new FileInputStream(fileName), cipher);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return inputStream;

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


}
