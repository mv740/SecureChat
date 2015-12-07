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
    private byte[][] serverNonceStore;
    private byte[][] clientNonceStore;


    //clients Public keys
    RSAPublicKey[] rsaPublicKeys;

    //server PrivateKey
    RSAPrivateKey rsaPrivateKeyServer;

    //DH- exchange
    private boolean[] SECURED_MODE;
    private SecretKey[] symmetricKeyStore;

    byte[][] ivStore;
    byte[][] sendStoreIV;
    byte[][] refreshStoreIV;
    boolean[] gotIv;


    // In Constructor, the user database is loaded.
    MyChatServer() {
        //try {
            //InputStream in = new FileInputStream("database.json");
            //JsonReader jsonReader = Json.createReader(in);
            //database = jsonReader.readArray();
            Authenticated = new boolean[2];
            SECURED_MODE = new boolean[2];
            symmetricKeyStore = new SecretKey[2];
            rsaPrivateKeyServer = Encryption.rsaLoadPrivateKey((new File("./certificate/private/server.key.pem")), "1q2w");
            rsaPublicKeys = new RSAPublicKey[2];
            serverNonceStore = new byte[2][];
            clientNonceStore = new byte[2][];
            ivStore = new byte[2][];
            gotIv = new boolean[2];
            sendStoreIV = new byte[2][];
            refreshStoreIV = new byte[2][];

//        } catch (FileNotFoundException e) {
//            System.err.println("Database file not found!");
//            System.exit(-1);
//        }
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

        ByteArrayInputStream is = new ByteArrayInputStream(buf);
        ObjectInput in = null;

        //http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
        //http://docstore.mik.ua/orelly/java-ent/security/ch13_07.htm

        try {
            ChatPacket p = null;

            //accept chat message/or logout from authenticated user only
            if (Authenticated[getUser(IsA)]) {

                if (SECURED_MODE[getUser(IsA)]) {

                    if (gotIv[getUser(IsA)]) {
                        p = Encryption.decryptWithAES(is, symmetricKeyStore[getUser(IsA)], ivStore[getUser(IsA)]);
                        gotIv[getUser(IsA)] = false; //used iv so reset
                        ivStore[getUser(IsA)] = null;
                    } else {
                        in = new ObjectInputStream(is);
                        Object o = in.readObject();
                        p = (ChatPacket) o;
                        ivStore[getUser(IsA)] = p.data;
                        gotIv[getUser(IsA)] = true; //got iv
                    }

                    if (p.request == ChatRequest.CHAT) {
                        // This is a chat message

                        byte[] hashMessage = Encryption.generateSHA256Digest(p.data);
                        if (Encryption.verifySignature(p.signature, hashMessage, rsaPublicKeys[getUser(IsA)])) {
                            // Whoever is sending it must be already logged in
                            if ((IsA && statA != "") || (!IsA && statB != "")) {
                                // Forward the original packet to the recipient

                                //receiver must be logged in to received
                                //SEND to authenticated user
                                if (IsA && statB != "") {
                                    //send message to other user
                                    sendMessageAndRefreshSender(IsA, p);

                                }
                                if (!IsA && statA != "") {
                                    sendMessageAndRefreshSender(IsA, p);

                                }
                            }
                        } else
                            errorMITM(IsA);

                    } else if (p.request == ChatRequest.LOGOUT) {
                        if (IsA) {
                            statA = "";
                        } else {
                            statB = "";
                        }
                        UpdateLogin(IsA, "");
                        String message = "LOGOUT";
                        byte[] messageHash = Encryption.generateSHA256Digest(message.getBytes("UTF-8"));
                        RespondtoClient(IsA, message, Encryption.generateSignature(messageHash, rsaPrivateKeyServer));
                        logoutUser(IsA);

                    }

                } else {

                    in = new ObjectInputStream(is);
                    Object o = in.readObject();
                    p = (ChatPacket) o;

                    if (p.request == ChatRequest.DH_PUBLIC_KEY) {

                        byte[] messageHash = Encryption.generateSHA256Digest(p.data);
                        if (Encryption.verifySignature(p.signature, messageHash, rsaPublicKeys[getUser(IsA)])) {
                            System.out.println("server start create public key");
                            byte[] serverPublicKey = serverCreatePublicPairKey(IsA, p.data);
                            sendDHPublicKeyToClient(IsA, serverPublicKey);
                            SECURED_MODE[getUser(IsA)] = true; //user is authenticated on the server side
                        } else
                            errorMITM(IsA);
                    }
                }
            } else {

                ObjectInput objectInput = new ObjectInputStream(is);
                Object object = objectInput.readObject();
                p = (ChatPacket) object;

                if (p.request == ChatRequest.Nonce) {

                    //recreate the hash of message
                    byte[] message = Encryption.concatenateMessage(p.rsaPublicKey.getEncoded(), p.cnonce);
                    byte[] hashMessage = Encryption.generateSHA256Digest(message);

                    //Authentication of message, no impersonation of user
                    if (Encryption.verifySignature(p.signature, hashMessage, p.rsaPublicKey)) {

                        System.out.println("VALID SIGNATURE");
                        //signature is valid, it is that user

                        byte[] clientNonce = Encryption.privateKeyDecryptionByte(p.cnonce, rsaPrivateKeyServer);
                        if (clientNonceStore[getUser(IsA)] != clientNonce) {
                            storePublicKeyAndClientNonce(IsA, p, clientNonce);

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
                            msg.snonce = Encryption.publicKeyEncryption(nonceServer, (rsaPublicKeys[getUser(IsA)]));

                            message = Encryption.concatenateMessage(msg.cnonce, msg.snonce);
                            hashMessage = Encryption.generateSHA256Digest(message);

                            msg.signature = Encryption.generateSignature(hashMessage, rsaPrivateKeyServer); //sign the client hashedMessage
                            System.out.println("send client nonce back + encrypted server nonce");
                            SerializeNSend(IsA, msg);
                        } else
                            errorReplayAttack();

                    } else {
                        errorMITM(IsA);
                    }

                }
                if (p.request == ChatRequest.LOGIN) {

                    System.out.println("server received last authentication msg");

                    byte[] hashMessage = Encryption.generateSHA256Digest(p.snonce);
                    if (Encryption.verifySignature(p.signature, hashMessage, (rsaPublicKeys[getUser(IsA)]))) {
                        //valid signature

                        if (serverNonceStore[getUser(IsA)] != p.snonce) {
                            //nonce is unique, was never reused... protect against replay attack
                            serverNonceStore[getUser(IsA)] = p.snonce; //store it for future authentication

                            Authenticated[getUser(IsA)] = true;
                            // We do not allow one user to be logged in on multiple
                            // clients
                            if (!p.uid.equals(IsA ? statB : statA)) {
                                //not already logged in
                                if (IsA) {
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

                            } else
                                errorReplayAttack();
                        }
                    }
                    if ((IsA ? statA : statB).equals("")) {
                        // Oops, this means a failure, we tell the client so
                        System.out.println("Server info : SYSTEM DENIED ACCESS");
                        String message = "access_denied";
                        //sign failure message
                        byte[] messageHash = Encryption.generateSHA256Digest(message.getBytes("UTF-8"));
                        RespondtoClient(IsA, message, Encryption.generateSignature(messageHash, rsaPrivateKeyServer));
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void errorReplayAttack() {
        System.out.println("server detected : REPLAY ATTACK");
    }

    /**
     * send iv + encrypted message to other user
     * then send iv + encrypted ack to original sender
     *
     * @param IsA user
     * @param p   message
     */
    private void sendMessageAndRefreshSender(boolean IsA, ChatPacket p) {
        //send message to other user
        ChatPacket ivMessage = new ChatPacket();
        ivMessage.request = ChatRequest.IV;
        sendStoreIV[getUser(!IsA)] = Encryption.generateIV();
        ivMessage.data = sendStoreIV[getUser(!IsA)];
        SerializeNSend(!IsA, ivMessage);
        p.signature = Encryption.generateSignature(Encryption.generateSHA256Digest(p.data), rsaPrivateKeyServer);
        SerializeNSend(!IsA, p);

        //refresh ui
        ivMessage = new ChatPacket();
        ivMessage.request = ChatRequest.IV;
        refreshStoreIV[getUser(IsA)] = Encryption.generateIV();
        ivMessage.data = refreshStoreIV[getUser(IsA)];
        System.out.println("server send new iv back to original client");
        SerializeNSend(IsA, ivMessage);
        System.out.println("system send back original message to refresh screen");
        refreshSenderUI(IsA, p);
    }

    private void errorMITM(boolean IsA) {
        System.out.println("MAN In the middle attack");
        reset(IsA);

    }

    /**
     * Diffie-Hellman public key is too big to encrypted by our RSA public key so we need to split it into two message
     * each part is encrypted and the signed
     *
     * @param IsA
     * @param serverPublicKey
     */
    private void sendDHPublicKeyToClient(boolean IsA, byte[] serverPublicKey) {

        //send to client
        ChatPacket msg = new ChatPacket();
        msg.request = ChatRequest.DH_PUBLIC_KEY;
        msg.uid = IsA ? statA : statB;
        msg.success = "Success";
        msg.data = serverPublicKey;
        byte[] messageHash = Encryption.generateSHA256Digest(msg.data);
        msg.signature = Encryption.generateSignature(messageHash, rsaPrivateKeyServer);
        SerializeNSend(IsA, msg);
        System.out.println("server send server public key");
        System.out.println("server side secured-mode activated for " + IsA);

    }

    /**
     * Create public Pair Key then create the shared secret key based on parameter from client user
     *
     * @param IsA
     * @param p
     * @param DHpublicKey
     * @return serverPublicKey
     */
    private byte[] serverCreatePublicPairKey(boolean IsA,byte[] DHpublicKey) {

        byte[] serverPublicKey = null;

        try {

            //get public key pair from other user
            System.out.println("Server receive client public key pair");
            //byte[] clientPublicKeyPair = Encryption.privateKeyDecryptionByte(p.data, rsaPrivateKeyServer);
            byte[] clientPublicKeyPair = DHpublicKey;


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
        SecretKey symmetricKeyAES = Encryption.generateAESKeyFromShareSecret(sharedSecret, Encryption.KeySize.KEY256);
        symmetricKeyStore[getUser(IsA)] = symmetricKeyAES;
    }

    private void storePublicKeyAndClientNonce(boolean IsA, ChatPacket p, byte[] clientNonce) {

        rsaPublicKeys[getUser(IsA)] = p.rsaPublicKey;
        clientNonceStore[getUser(IsA)] = clientNonce;

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
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(os);
            out.writeObject(p);
            byte[] packet = os.toByteArray();


            if (SECURED_MODE[getUser(IsA)] && Authenticated[getUser(IsA)] && p.request != ChatRequest.IV) {

                if (p.request == ChatRequest.CHAT_ACK) {
                    packet = Encryption.encryptWithAES(packet, symmetricKeyStore[getUser(IsA)], refreshStoreIV[getUser(IsA)]);
                } else
                    packet = Encryption.encryptWithAES(packet, symmetricKeyStore[getUser(IsA)], sendStoreIV[getUser(IsA)]);

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

        SerializeNSend(IsA, p);
    }


    private void logoutUser(Boolean IsA) {
        System.out.println("Logout user :" + IsA);
        if (IsA) {
            this.UpdateServerLog("server stop authenticated connection with alice");
        } else
            this.UpdateServerLog("server stop authenticated connection with Bob");
        reset(IsA);

    }

    public void reset(boolean IsA) {
        Authenticated[getUser(IsA)] = false;
        SECURED_MODE[getUser(IsA)] = false;
        symmetricKeyStore[getUser(IsA)] = null;
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

