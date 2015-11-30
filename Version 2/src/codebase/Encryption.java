package codebase;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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




    public static OutputStream encrypt(String fileLocation, SecretKey key, byte[] iv) {
        Cipher cipher;
        OutputStream outputStream = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            outputStream = new CipherOutputStream(new FileOutputStream(fileLocation), cipher);
            //System.out.println(fileLocation);

            String ivFileName = getIVFileName(fileLocation);
            //http://javapapers.com/java/java-file-encryption-decryption-using-aes-password-based-encryption-pbe/
            //storing cbc iv in a specific folder
            createIVFile(cipher, ivFileName);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return outputStream;

    }

    private static String getIVFileName(String fileLocation) {
        String name = findUserByLog(fileLocation);
        return "log/"+name+".IV";
    }

    private static void createIVFile(Cipher cipher, String ivFileName) throws InvalidParameterSpecException, IOException {
        FileOutputStream ivOutFile = new FileOutputStream(ivFileName);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        ivOutFile.write(iv);
        ivOutFile.close();
    }

    private static String findUserByLog(String fileLocation) {
        Pattern pattern = Pattern.compile("/(.+?).json");
        Matcher matcher = pattern.matcher(fileLocation);
        matcher.find();
        return matcher.group(1);

    }

    public static InputStream decrypt(String fileLocation, SecretKey key, byte[] iv) {
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

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return inputStream;

    }

    public static byte[] retrieveIV(String ivFileName)  {

        byte[] iv = new byte[16];
        try {
            FileInputStream findIV = new FileInputStream(ivFileName);
            findIV.read(iv);
            findIV.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return iv;
    }

    public static void storeIV(byte[] iv, String fileLocation)
    {
        String ivFileName = getIVFileName(fileLocation);
        FileOutputStream ivOutFile;
        try {
            ivOutFile = new FileOutputStream(ivFileName);
            ivOutFile.write(iv);
            ivOutFile.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


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
