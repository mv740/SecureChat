package codebase;

import org.apache.commons.ssl.PKCS8Key;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by micha on 11/14/2015.
 */
public class Encryption {


    public static SecretKey generateAESKey(byte[] sharedSecret) {
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



    public static RSAPublicKey rsaLoadPublicKey(File path)
    {
        RSAPublicKey rsaPublicKey = null;

        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("x.509");
            java.security.cert.Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
            rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return rsaPublicKey;
    }

    public static  RSAPrivateKey rsaLoadPrivateKey(File path)
    {
        RSAPrivateKey rsaPrivateKey= null;
        //http://juliusdavies.ca/commons-ssl/pkcs8.html
        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            PKCS8Key pkcs8Key = new PKCS8Key(fileInputStream,"1q2w".toCharArray());
            byte[] decrypted = pkcs8Key.getDecryptedBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decrypted );

            //create Java privateKey
            if(pkcs8Key.isRSA())
            {
                rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
            }


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return  rsaPrivateKey;
    }


    public static byte[] generateSignature(byte[] toBeSigned, RSAPrivateKey rsaPrivateKey)
    {
        byte[] signature =null;
        try {
            Signature signProcess = Signature.getInstance("SHA1withRSA");
            signProcess.initSign(rsaPrivateKey);
            signProcess.update(toBeSigned); //Updates the data to be signed
            signature = signProcess.sign();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return signature;
    }

    public static boolean verifySignature(byte[] signature ,byte[]signedData,  RSAPublicKey rsaPublicKey)
    {
        //https://www.flexiprovider.de/examples/ExampleSMIMEverify.html
        boolean isValid = false;
        try {
            Signature signProcess = Signature.getInstance("SHA1withRSA");
            signProcess.initVerify(rsaPublicKey);
            signProcess.update(signedData);//Updates the data to be verified

            isValid = signProcess.verify(signature);
            if(!isValid)
            {
                System.out.println("error: validation of the signature failed");
            }


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return isValid;
    }

    public static byte[] publicKeyEncryption(byte[] plaintext, RSAPublicKey rsaPublicKey)
    {
        Cipher cipher;
        byte[] cipherText = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            cipherText = cipher.doFinal(plaintext);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static byte[] privateKeyDecryptionByte(byte[] cipherText, RSAPrivateKey rsaPrivateKey)
    {
        Cipher cipher;
        byte[] plainText = null;
        try {

            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            plainText = cipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return plainText;
    }

    public static ChatPacket PrivateKeyDecryption1(ByteArrayInputStream byteArrayInputStream, RSAPrivateKey rsaPrivateKey)
    {
        Cipher cipher;
        ChatPacket chatPacket = null;
        try {
            System.out.println("key"+rsaPrivateKey.getModulus().bitLength());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            CipherInputStream cis = new CipherInputStream(byteArrayInputStream, cipher);
            //plainText = cipher.doFinal(cipherText);

            ObjectInput objectInput = new ObjectInputStream(cis);
            Object object = objectInput.readObject();
            chatPacket = (ChatPacket) object;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return chatPacket;
    }

    public static byte[] PrivateKeyDecryptionPacket(byte[] data, RSAPrivateKey rsaPrivateKey)
    {
        Cipher cipher;
        byte[] plainText = null;
        try {
            System.out.println("key"+rsaPrivateKey.getModulus().bitLength());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            plainText = cipher.doFinal(data);



        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return plainText;
    }


    /**
     * Encrypt Stream
     * AES encryption using CBC mode with PKCS5Padding
     *
     * @param fileLocation 
     * @param key
     * @param iv
     * @return
     */
    public static OutputStream encryptStream(String fileLocation, SecretKey key, byte[] iv) {
        Cipher cipher;
        OutputStream outputStream = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            outputStream = new CipherOutputStream(new FileOutputStream(fileLocation), cipher);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
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


    /**
     * get the iv file location based on the user's chatlog
     * Every chatlog file has a machting iv using a structure : chat log "chatlog-alice.json" with iv "chatlog-alice.iv"
     *
     * @param fileLocation provide chatlogfile location
     * @return matched iv location
     */
    private static String getIVFileLocation(String fileLocation) {
        String name = findUserByLog(fileLocation);
        return "log/"+name+".IV";
    }


    private static String findUserByLog(String fileLocation) {
        Pattern pattern = Pattern.compile("/(.+?).json");
        Matcher matcher = pattern.matcher(fileLocation);
        matcher.find();
        return matcher.group(1);

    }

    public static byte[] AESencrypt(byte[] plaintext, SecretKey symmetricKeyAES) {
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

    public static ChatPacket AESdecrypt(ByteArrayInputStream byteArrayInputStream, SecretKey symmetricKeyAES) {
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



    /**
     * decrypt stream using AES with cbc mode
     * @param fileLocation
     * @param key
     * @param iv
     * @return
     */
    public static InputStream decryptStream(String fileLocation, SecretKey key, byte[] iv) {
        Cipher cipher;
        InputStream inputStream = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            inputStream = new CipherInputStream(new FileInputStream(fileLocation), cipher);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {

            System.err.println("Chatlog file could not be opened.");

        }  catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return inputStream;

    }



    public static byte[] generateIV()
    {
        byte[] iv = new byte[16];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(iv);

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
