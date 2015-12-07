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
import java.security.spec.PKCS8EncodedKeySpec;


/**
 * Created by micha on 11/14/2015.
 */
public class Encryption {

    public enum KeySize {
        KEY128, KEY192, KEY256
    }

    /**
     * generate an AES Key with a Specific size based on a shared secret
     *
     * @param sharedSecret
     * @param keySize
     * @return symmetric aes key
     */
    public static SecretKey generateAESKeyFromShareSecret(byte[] sharedSecret, KeySize keySize) {
        //to be able to use 256 AES key, you need to install this http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
        //Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files
        //without them,the default java environment is limiting us to 128 key

        MessageDigest md;
        SecretKey aesKey = null;
        try {
            md = MessageDigest.getInstance("SHA-256");

            byte[] hashSharedKey = md.digest(sharedSecret);

            if (keySize == KeySize.KEY128) {
                //http://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml
                //It turns out that the Cipher class will generally not allow encryption with a key size of more than 128 bits
                byte[] AES128key = new byte[hashSharedKey.length / 2]; //we need 128 bit but we have 256 bits
                System.arraycopy(hashSharedKey, 0, AES128key, 0, AES128key.length);
                aesKey = new SecretKeySpec(AES128key, "AES");
            } else if (keySize == KeySize.KEY192) {
                byte[] AES192key = new byte[192];
                System.arraycopy(hashSharedKey, 0, AES192key, 0, AES192key.length);
                aesKey = new SecretKeySpec(AES192key, "AES");
            } else if (keySize == KeySize.KEY256) {
                aesKey = new SecretKeySpec(hashSharedKey, "AES"); //take all the hash
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return aesKey;
    }

    public static RSAPublicKey rsaLoadPublicKey(File path) {
        RSAPublicKey rsaPublicKey = null;

        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("x.509");
            java.security.cert.Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
            rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        } catch (FileNotFoundException | CertificateException e) {
            e.printStackTrace();
        }
        return rsaPublicKey;
    }


    public static RSAPrivateKey rsaLoadPrivateKey(File path, String password) {
        RSAPrivateKey rsaPrivateKey = null;
        //http://juliusdavies.ca/commons-ssl/pkcs8.html
        try {
            FileInputStream fileInputStream = new FileInputStream(path);
            PKCS8Key pkcs8Key = new PKCS8Key(fileInputStream, password.toCharArray());
            byte[] decrypted = pkcs8Key.getDecryptedBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decrypted);

            //create Java privateKey
            if (pkcs8Key.isRSA()) {
                rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
            }

        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        return rsaPrivateKey;
    }


    public static byte[] generateSignature(byte[] toBeSigned, RSAPrivateKey rsaPrivateKey) {
        byte[] signature = null;
        try {
            Signature signProcess = Signature.getInstance("SHA1withRSA");
            signProcess.initSign(rsaPrivateKey);
            signProcess.update(toBeSigned); //Updates the data to be signed
            signature = signProcess.sign();

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return signature;
    }

    /**
     * verify the authenticity of the signature
     * will detect if the message has been tampered by someone
     *
     * @param signature    signed message Hash
     * @param signedData   message hash
     * @param rsaPublicKey
     * @return success/failure
     */
    public static boolean verifySignature(byte[] signature, byte[] signedData, RSAPublicKey rsaPublicKey) {
        //https://www.flexiprovider.de/examples/ExampleSMIMEverify.html
        boolean isValid = false;
        try {
            Signature signProcess = Signature.getInstance("SHA1withRSA");
            signProcess.initVerify(rsaPublicKey);
            signProcess.update(signedData);//Updates the data to be verified
            isValid = signProcess.verify(signature);

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return isValid;
    }

    /**
     * RSA encryption operation using the corresponding public key
     *
     * @param plaintext    plainText message
     * @param rsaPublicKey public key
     * @return cipherText
     */
    public static byte[] publicKeyEncryption(byte[] plaintext, RSAPublicKey rsaPublicKey) {
        Cipher cipher;
        byte[] cipherText = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            cipherText = cipher.doFinal(plaintext);

        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    /**
     * RSA decryption operation using the corresponding rsa private key
     *
     * @param cipherText    encrypted message
     * @param rsaPrivateKey private key
     * @return plainText
     */
    public static byte[] privateKeyDecryptionByte(byte[] cipherText, RSAPrivateKey rsaPrivateKey) {
        Cipher cipher;
        byte[] plainText = null;
        try {

            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            plainText = cipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return plainText;
    }


    /**
     * encrypt our plaintext packet using a aes key
     *
     * @param plaintext       clear packet
     * @param symmetricKeyAES key
     * @param iv              unique iv
     * @return cipher packet
     */
    public static byte[] encryptWithAES(byte[] plaintext, SecretKey symmetricKeyAES, byte[] iv) {
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKeyAES, new IvParameterSpec(iv));
            encrypted = cipher.doFinal(plaintext);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    /**
     * Decrypt encrypted stream using our symmetric AES key with the corresponding iv
     * Convert that plain stream back into chatPacket object
     *
     * @param byteArrayInputStream encrypted stream
     * @param symmetricKeyAES      AES key
     * @param iv
     * @return ChatPacket object
     */
    public static ChatPacket decryptWithAES(ByteArrayInputStream byteArrayInputStream, SecretKey symmetricKeyAES, byte[] iv) {
        Cipher cipher;
        ChatPacket chatPacket = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKeyAES, new IvParameterSpec(iv));
            CipherInputStream cis = new CipherInputStream(byteArrayInputStream, cipher);


            ObjectInput objectInput = new ObjectInputStream(cis);
            Object object = objectInput.readObject();
            chatPacket = (ChatPacket) object;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | ClassNotFoundException | IOException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return chatPacket;
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(iv);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return iv;

    }

    /**
     * Generate a random unique "number" to be used during the authentication protocol (protect against replay attack)
     *
     * @return unique random byte[] "number"
     */
    public static byte[] generateNonce() {
        //https://www.cigital.com/blog/proper-use-of-javas-securerandom/
        //http://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html#getInstanceStrong--
        SecureRandom secureRandom;
        byte[] bytes = null;
        try {
            //SecureRandom secureRandom = new SecureRandom();
            secureRandom = SecureRandom.getInstanceStrong(); // Java 8
            bytes = new byte[16];
            secureRandom.nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return bytes;
    }


    public static byte[] generateSHA256Digest(byte[] message) {
        byte[] hashedMessage = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(message);
            hashedMessage = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hashedMessage;
    }

    /**
     * Concatenate two byte[] messages into one
     *
     * @param message1
     * @param message2
     * @return
     */
    public static byte[] concatenateMessage(byte[] message1, byte[] message2) {
        byte[] result = null;

        //http://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(message1);
            outputStream.write(message2);

            result = outputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;

    }


}
