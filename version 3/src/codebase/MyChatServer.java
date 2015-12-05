package codebase;

import infrastructure.ChatServer;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonReader;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


/**
 * ChatServer implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * <p>
 * Here MyChatServer (of your choice) extends it and implements the actual
 * server-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 */
class MyChatServer extends ChatServer {

    /**
     * A Json array loaded from disk file storing plaintext uids and pwds.
     */
    JsonArray database;

    /**
     * Client login status; "" indicates not logged in or otherwise is set to
     * uid.
     **/
    String statA = "";
    String statB = "";

    //who is authenticated [Alice, Bob]
    private boolean[] Authenticated;

    //server nonce store. used to detect replay attack
    private byte[] serverNonceA;
    private byte[] serverNonceB;


    //clients Public keys
    RSAPublicKey rsaPublicKeyAlice;
    RSAPublicKey rsaPublicKeyBob;

    //server PrivateKey
    RSAPrivateKey rsaPrivateKeyServer;

    //DH- exchange
    private boolean[] SECURED_MODE;
    private SecretKey[] symmetricKeyStore;


    // In Constructor, the user database is loaded.
    MyChatServer() {
        try {
            InputStream in = new FileInputStream("database.json");
            JsonReader jsonReader = Json.createReader(in);
            database = jsonReader.readArray();
            Authenticated = new boolean[2];
            SECURED_MODE = new boolean[2];
            symmetricKeyStore = new SecretKey[2];

            //URL url = getClass().getResource("ListStopWords.txt");
            //String workingDirectory = System.getProperty("certificate");
            //System.out.println(workingDirectory);

            rsaPrivateKeyServer = Encryption.rsaLoadPrivateKey((new File("./certificate/private/server.key.pem")));


        } catch (FileNotFoundException e) {
            System.err.println("Database file not found!");
            System.exit(-1);
        }
    }


    /**
     * Methods invoked by the network stack
     */

    /**
     * Overrides the function in ChatServer Whenever a packet is received this
     * method is called and IsA indicates whether it is from A (or B) with the
     * byte array of the raw packet
     */
    public void PacketReceived(boolean IsA, byte[] buf) {
        //System.out.println(buf.length);
        //WTF IS GOING HERE
        //buf = Arrays.copyOfRange(buf,0, 256);
        //System.out.println("2-ENCRYPTED =>"+Arrays.toString(buf));
        //System.out.println("size "+buf.length);

        ByteArrayInputStream is = new ByteArrayInputStream(buf);
        ObjectInput in = null;

        //http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
        //http://docstore.mik.ua/orelly/java-ent/security/ch13_07.htm


        try {
            ChatPacket p = null;

            //accept chat message/or logout from authenticated user only
            if (Authenticated[getUser(IsA)]) {

                if(SECURED_MODE[getUser(IsA)])
                {
                    p = Encryption.AESdecrypt(is,symmetricKeyStore[getUser(IsA)]);

                    if (p.request == ChatRequest.CHAT) {
                        // This is a chat message

                        // Whoever is sending it must be already logged in
                        if ((IsA && statA != "") || (!IsA && statB != "")) {
                            // Forward the original packet to the recipient


                            //receiver must be logged in to received
                            //SEND to authenticated user
                            if (IsA) {
                                SerializeNSend(!IsA, p);
                                if (statB != "") {
                                    refreshSenderUI(IsA, p);

                                }
                            }
                            if (!IsA) {
                                SerializeNSend(!IsA, p);

                                if (statA != "") {
                                    refreshSenderUI(IsA, p);
                                }
                            }
                        }
                    }else if (p.request == ChatRequest.LOGOUT) {
                        if (IsA) {
                            statA = "";
                        } else {
                            statB = "";
                        }
                        UpdateLogin(IsA, "");
                        RespondtoClient(IsA, "LOGOUT", null);
                        securedConnectionStop(IsA);


                    }

                }else {

                    in = new ObjectInputStream(is);
                    Object o = in.readObject();
                    p = (ChatPacket) o;

                    if (p.request == ChatRequest.DH_PUBLIC_KEY) {


                        System.out.println("server start create public key");
                        byte[] serverPublicKey = serverCreatePublicPairKey(IsA, p);

                        //send to client
                        ChatPacket msg = new ChatPacket();
                        msg.request = ChatRequest.DH_PUBLIC_KEY;
                        msg.uid = IsA ? statA : statB;
                        msg.success = "Success";
                        msg.data = Encryption.publicKeyEncryption(serverPublicKey, (IsA ? rsaPublicKeyAlice : rsaPublicKeyBob));
                        //msg.signature = Encryption.generateSignature(msg.uid.getBytes("UTF-8"), rsaPrivateKeyServer);

                        System.out.println("server send server public key");
                        System.out.println("server side secured-mode activated for " + IsA);
                        SerializeNSend(IsA, msg);
                        SECURED_MODE[getUser(IsA)] = true;

                    }
                }
            } else {

                ObjectInput objectInput = new ObjectInputStream(is);
                Object object = objectInput.readObject();
                p = (ChatPacket) object;

                //p = Encryption.PrivateKeyDecryption1(is, rsaPrivateKeyServer);

                if (p.request == ChatRequest.Nonce) {


                    //recreate the hash of message
                    byte[] message = Encryption.concatenateMessage(p.rsaPublicKey.getEncoded(),p.cnonce);
                    byte[] hashMessage = Encryption.generateSHA256Digest(message);

                    //Authentication of message, no impersonation of user
                    if (Encryption.verifySignature(p.signature, hashMessage, p.rsaPublicKey)) {

                        System.out.println("VALID SIGNATURE");
                        //signature is valid, it is that user
                        storePublicKeyAndClientNonce(IsA, p);

                        //create a challenge for the client
                        System.out.println("create server nonce");
                        byte[] nonceServer = Encryption.generateNonce();

                        //send to client
                        ChatPacket msg = new ChatPacket();
                        msg.request = ChatRequest.Nonce;
                        msg.uid = IsA ? statA : statB;
                        msg.success = "ok";
                        //msg.cnonce = IsA ? clientNonceA : clientNonceB;
                        msg.cnonce = Encryption.privateKeyDecryptionByte(p.cnonce, rsaPrivateKeyServer);
                        msg.snonce = Encryption.publicKeyEncryption(nonceServer, (IsA ? rsaPublicKeyAlice : rsaPublicKeyBob));

                        message = Encryption.concatenateMessage(msg.cnonce,msg.snonce);
                        hashMessage = Encryption.generateSHA256Digest(message);

                        msg.signature = Encryption.generateSignature(hashMessage, rsaPrivateKeyServer); //sign the client hashedMessage
                        System.out.println("send client nonce back + encrypted server nonce");
                        SerializeNSend(IsA, msg);
                    } else {
                        System.out.println("WARNING MAN IN THE MIDDLE ATTACK");
                    }


                }
                if (p.request == ChatRequest.LOGIN) {

                    System.out.println("server received last authentication msg");

                    byte[] hashMessage = Encryption.generateSHA256Digest(p.snonce);

                    if (Encryption.verifySignature(p.signature, hashMessage, (IsA ? rsaPublicKeyAlice : rsaPublicKeyBob))) {
                        //valid signature
                        if (IsA) {
                            if (serverNonceA != p.snonce) {
                                //once is unique, was never reused ... protect agains replay attack
                                //store value for future authentication
                                serverNonceA = p.snonce;
                            } else {
                                System.out.println("server nonce was already used!!! Attack detected");
                            }
                        } else {
                            if (serverNonceB != p.snonce) {
                                //once is unique, was never reused ... protect agains replay attack
                                //store value for future authentication
                                serverNonceB = p.snonce;
                            } else {
                                System.out.println("server nonce was already used!!! Attack detected");
                            }
                        }

                        Authenticated[getUser(IsA)] = true;
                        // We do not allow one user to be logged in on multiple
                        // clients
                        if (!p.uid.equals(IsA ? statB : statA)) {
                            //not already logged in
                            if (IsA) {
                                System.out.println("server test : uid =" + p.uid);
                                statA = p.uid;
                            } else {
                                statB = p.uid;
                            }

                            // Update the UI to indicate this
                            UpdateLogin(IsA, IsA ? statA : statB);

                            // Inform the client that it was successful
                            System.out.println("server sucessful login");
                            String message = "LOGIN";
                            //sign successful login
                            hashMessage = Encryption.generateSHA256Digest(message.getBytes("UTF-8"));
                            RespondtoClient(IsA, message, Encryption.generateSignature(hashMessage, rsaPrivateKeyServer));
                        }
                    }


                    if ((IsA ? statA : statB).equals("")) {
                        // Oops, this means a failure, we tell the client so
                        System.out.println("Server info : SYSTEM DENIED ACCESS");
                        String message = "access_denied";
                        //sign failure message
                        RespondtoClient(IsA, message, Encryption.generateSignature(message.getBytes("UTF-8"), rsaPrivateKeyServer));
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * Create public Pair Key then create the shared secret key based on parameter from client user
     *
     *
     * @param IsA
     * @param p
     * @return serverPublicKey
     */
    private byte[] serverCreatePublicPairKey(boolean IsA, ChatPacket p) {

        byte[] serverPublicKey =null;

        try {

            //get public key pair from other user
            System.out.println("Server receive client public key pair");
            byte[] clientPublicKeyPair = Encryption.privateKeyDecryptionByte(p.data, rsaPrivateKeyServer);
            if(clientPublicKeyPair.length ==0)
            {
                System.out.println("clientPublicKeyPair size error");
            }

            //Instantiate DH public key from the encoded key material
            KeyFactory serverKeyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyPair);
            PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);

            //get DH parameter from client public key
            DHParameterSpec dhParamSpec = ((DHPublicKey) clientPubKey).getParams();

            //server create his own public key
            KeyPairGenerator serverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            try {
                serverKeyPairGenerator.initialize(dhParamSpec);
                KeyPair serverKeyPair = serverKeyPairGenerator.generateKeyPair();

                //server create and initialize keyAgreement
                KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("DH");
                serverKeyAgreement.init(serverKeyPair.getPrivate());

                System.out.println("server create shared secret key");
                //create shared secret KEY
                serverKeyAgreement.doPhase(clientPubKey, true);
                byte[] sharedSecret = serverKeyAgreement.generateSecret();
                System.out.println("server sharwed key size " +sharedSecret.length);

                generateSharedAESKey(IsA, sharedSecret);


                //server encode his public key and send to client
                serverPublicKey = serverKeyPair.getPublic().getEncoded();



            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return serverPublicKey;
    }

    private void generateSharedAESKey(boolean IsA, byte[] sharedSecret) {
        //create shared AES symmetric key
        SecretKey symmetricKeyAES = Encryption.generateAESKey(sharedSecret);
        System.out.println("TEST GET USER" + getUser(IsA));
        symmetricKeyStore[getUser(IsA)] = symmetricKeyAES;
    }

    private void storePublicKeyAndClientNonce(boolean IsA, ChatPacket p) {
        byte[] clientNonce = Encryption.privateKeyDecryptionByte(p.cnonce, rsaPrivateKeyServer);

        if (IsA) {
            //the user sending the msg is alice
            rsaPublicKeyAlice = p.rsaPublicKey; //store public key
            System.out.println("stored rsaPublicKeyAlice");
            //decrypt nonce send by alice
            //clientNonceA = clientNonce;

        } else {
            //the user sending the msg is bob
            rsaPublicKeyBob = p.rsaPublicKey; //store public key
            System.out.println("stored rsaPublicKeyBob");
            //decrypt nonce send by Bob
            //clientNonceB = clientNonce;
        }
    }

    private void clientNounceReceivedLog(ChatPacket p) {
        System.out.println("client nonce received " + Arrays.toString(p.cnonce));
    }

    private void refreshSenderUI(boolean IsA, ChatPacket p) {
        // Flip the uid and send it back to the sender for updating
        // chat history
        p.request = ChatRequest.CHAT_ACK;
        p.uid = (IsA ? statB : statA);
        SerializeNSend(IsA, p);
    }


    /**
     * Methods for updating UI
     */

    // You can use this.UpdateServerLog("anything") to update the TextField on
    // the server portion of the UI
    // when needed

    /**
     * Methods invoked locally
     */

    /**
     * This method serializes (into byte[] representation) a Java object
     * (ChatPacket) and sends it to the corresponding recipient (A or B)
     */
    private void SerializeNSend(boolean IsA, ChatPacket p) {

        //System.out.println("sending to user ALICE: " + IsA);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(os);
            out.writeObject(p);
            byte[] packet = os.toByteArray();


            if(SECURED_MODE[getUser(IsA)] && Authenticated[getUser(IsA)])
            {
                packet = Encryption.AESencrypt(packet,symmetricKeyStore[getUser(IsA)]);
            }
            SendtoClient(IsA, packet);


        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }


    /**
     * This method composes the packet needed to respond to a client (indicated
     * by IsA) regarding whether the login/logout request was successful
     * p.success would be "" if failed or "LOGIN"/"LOGOUT" respectively if
     * successful
     */
    void RespondtoClient(boolean IsA, String Success, byte[] signature) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.RESPONSE;
        p.uid = IsA ? statA : statB;
        p.success = Success;
        p.signature = signature;

        System.out.println("server side signature" + p.signature.length);


        SerializeNSend(IsA, p);
    }


    private void securedConnectionStart(ChatPacket p, Boolean IsA) {
        if (IsA) {
            this.UpdateServerLog("server initiate secured connection with alice");
        } else
            this.UpdateServerLog("server initiate secured connection with Bob");
        Authenticated[getUser(IsA)] = true;
    }


    private void securedConnectionStop(Boolean IsA) {
        //System.out.println("DEACTIVATED ENCRYPTION");
        if (IsA) {
            this.UpdateServerLog("server stop authenticated connection with alice");
        } else
            this.UpdateServerLog("server stop authenticated connection with Bob");
        Authenticated[getUser(IsA)] = false;

    }


    /**
     * convert true/false into binary
     *
     * @param IsA is Alice
     * @return binary 0/1
     */
    public static int getUser(boolean IsA) {
        ////http://stackoverflow.com/questions/3793650/convert-boolean-to-int-in-java
        // bool to integer
        return Boolean.compare(IsA, false);
    }

}

