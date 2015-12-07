package codebase;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.*;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import infrastructure.ChatClient;

/**
 * ChatClient implements the fundamental communication capabilities for your
 * server, but it does not take care of the semantics of the payload it carries.
 * <p>
 * Here MyChatClient (of your choice) extends it and implements the actual
 * client-side protocol. It must be replaced with/adapted for your designed
 * protocol.
 * <p>
 * Note that A and B are distinguished by the boolean value with the
 * constructor.
 */
class MyChatClient extends ChatClient {

    private String uid = null;
    private boolean Authenticated = false;


    private byte[] clientNonce;

    //certificates Public/Private
    RSAPublicKey rsaPublicKey;
    RSAPrivateKey rsaPrivateKey;

    //server publicKey
    RSAPublicKey rsaPublicKeyServer;

    //Diffie–Hellman key exchange
    private KeyPair keyPairClient = null;
    private SecretKey symmetricKeyAES;
    boolean SECURED_MODE;

    byte[] ivStore;
    byte[] sendIV;
    boolean gotIV =false;

    MyChatClient(boolean IsA) {


        // This is the minimum constructor you must
        // preserve
        super(IsA); // IsA indicates whether it's client A or B
        startComm(); // starts the communication

    }

    /**
     * The current user that is logged in on this client
     **/
    public String curUser = "";

    /**
     * The Json array storing the internal history state
     */
    JsonArray chatlog;

    /**
     * Actions received from UI
     */

    /**
     * Someone clicks on the "Login" button
     */
    public void LoginRequestReceived(String uid, String pwd) {
        if (!Authenticated) {
            this.uid = uid;
            System.out.println("client ask for server nonce");
            getNonce(uid);
        }
    }


    //ask a nonce from the server
    public void getNonce(String uid) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.Nonce;
        p.uid = uid;

        p.rsaPublicKey = rsaPublicKey; //send her public key to server
        p.cnonce = Encryption.publicKeyEncryption(Encryption.generateNonce(), rsaPublicKeyServer); //create client nonce and encrypt it
        byte[] message = Encryption.concatenateMessage(rsaPublicKey.getEncoded(),p.cnonce);
        byte[] messageHash = Encryption.generateSHA256Digest(message);
        p.signature = Encryption.generateSignature(messageHash, rsaPrivateKey); //we prove that we are the one sending this message by signing the hash of the msg

        SerializeNSend(p);
    }





    /**
     * Callback invoked when the certificate file is selected
     *
     * @param path Selected certificate file's path
     */
    public void FileLocationReceivedCert(File path) {
        // TODO
        System.out.println("FileLocationReceivedCert");
        rsaPublicKey = Encryption.rsaLoadPublicKey(path);
    }

    /**
     * Callback invoked when the private key file is selected
     *
     * @param path Selected private key file's path
     */
    public void FileLocationReceivedPriv(File path) {
        // TODO
        System.out.println("FileLocationReceivedPriv");
        rsaPrivateKey = Encryption.rsaLoadPrivateKey(path,"1q2w");
    }

    /**
     * Callback invoked when an authentication mode is selected.
     *
     * @param IsPWD True if password-based (false if certificate-based).
     */
    public void ReceivedMode(boolean IsPWD) {
        // TODO
        if (!IsPWD) {
            //load server certificate
            rsaPublicKeyServer = Encryption.rsaLoadPublicKey(new File("./certificate/server.crt"));
            System.out.println("PUBLIC PRIVATE KEY SYSTEM BEGIN");
        }
    }


    /**
     * Someone clicks on the "Logout" button
     */
    public void LogoutRequestReceived() {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.LOGOUT;

        SerializeNSend(p);
    }

    /**
     * Someone clicks on the "Send" button
     *
     * @param message Message to be sent (user's level)
     */
    public void ChatRequestReceived(byte[] message) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.CHAT;
        p.uid = curUser;
        p.data = message;
        if (Authenticated) {

            ChatPacket ivMessage = new ChatPacket();
            ivMessage.request = ChatRequest.IV;
            sendIV = Encryption.generateIV();
            ivMessage.data = sendIV;
            System.out.println("client: "+uid +" send iv to server");
            SerializeNSend(ivMessage);

            p.signature = Encryption.generateSignature(Encryption.generateSHA256Digest(p.data),rsaPrivateKey);
            System.out.println("client: "+uid+ "send message to server");
            SerializeNSend(p);
        }

    }

    /**
     * Methods for updating UI
     */

    /**
     * This will refresh the messages on the UI with the Json array chatlog
     */
    void RefreshList() {
        String[] list = new String[chatlog.size()];
        for (int i = 0; i < chatlog.size(); i++) {
            String from = chatlog.getJsonObject(i).getString("from");
            String to = chatlog.getJsonObject(i).getString("to");
            String message = chatlog.getJsonObject(i).getString("message");
            list[i] = (from + "->" + to + ": " + message);
        }
        UpdateMessages(list);
    }

    /**
     * Methods invoked by the network stack
     */

    /**
     * Callback invoked when a packet has been received from the server
     * (as the client only talks with the server, but not the other client)
     *
     * @param buf Incoming message
     */
    public void PacketfromServer(byte[] buf) {
        ByteArrayInputStream is = new ByteArrayInputStream(buf);
        ObjectInput in = null;
        ChatPacket p;
        try {


            if(Authenticated && SECURED_MODE)
            {
                if(gotIV)
                {
                    p = Encryption.decryptWithAES(is, symmetricKeyAES, ivStore);
                    gotIV=false; //used iv so reset
                    ivStore=null;
                    System.out.println("client:"+uid+" Used IV ");
                }else
                {
                    in = new ObjectInputStream(is);
                    Object o = in.readObject();
                    p = (ChatPacket) o;

                    if(p.request == ChatRequest.IV)
                    {
                        ivStore= p.data;
                        gotIV = true; //got iv
                        System.out.println("client :"+uid +" received Iv from server");
                    }else {
                        System.out.println("we got something else :" +p.request);
                    }

                }

                if (p.request == ChatRequest.CHAT && !curUser.equals("")) {
                    // A new chat message received
                    byte[] hash = Encryption.generateSHA256Digest(p.data);
                    if(Encryption.verifySignature(p.signature,hash,rsaPublicKeyServer))
                    {
                        Add1Message(p.uid, curUser, p.data);
                    }
                    else
                        errorMITM();
                } else if (p.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
                    // This was sent by us and now it's confirmed by the server, add
                    // it to chat history
                    byte[] hash = Encryption.generateSHA256Digest(p.data);
                    if(Encryption.verifySignature(p.signature,hash,rsaPublicKeyServer))
                    {
                        Add1Message(curUser, p.uid, p.data);
                    }
                    else
                        errorMITM();
                }

            }else {
                in = new ObjectInputStream(is);
                Object o = in.readObject();
                p = (ChatPacket) o;
            }

            if(Authenticated && !SECURED_MODE)
            {
                if(p.request == ChatRequest.DH_PUBLIC_KEY)
                {
                    System.out.println("client receive public from server");
                        byte [] messageHash = Encryption.generateSHA256Digest(p.data);
                        if(Encryption.verifySignature(p.signature,messageHash,rsaPublicKeyServer))
                        {
                            byte[] publicKey = Encryption.privateKeyDecryptionByte(p.data,rsaPrivateKey);
                            generateSharedSecretKey(publicKey);
                        }else
                            errorMITM();
                }



            }

            if (p.request == ChatRequest.Nonce) {

                System.out.println("client receive server nonce from server");

                byte[] message = Encryption.concatenateMessage(p.cnonce,p.snonce);
                byte[] hashMessage = Encryption.generateSHA256Digest(message);

                //verify that we are receiving from the real server
                if (Encryption.verifySignature(p.signature, hashMessage, rsaPublicKeyServer)) {

                    if (clientNonce != p.cnonce) {
                        //store it to check for future  authentication
                        clientNonce = p.cnonce;
                        //client nonce can never be reused
                        // passed nonce challenge,

                        //server still need to authenticate us
                        ChatPacket msg = new ChatPacket();
                        System.out.println("client send back the server nonce");
                        msg.request = ChatRequest.LOGIN;
                        msg.uid = this.uid;
                        msg.snonce = Encryption.privateKeyDecryptionByte(p.snonce, rsaPrivateKey);

                        hashMessage = Encryption.generateSHA256Digest(msg.snonce);

                        msg.signature = Encryption.generateSignature(hashMessage, rsaPrivateKey); //sign bob's hashed challenge
                        SerializeNSend(msg);

                    } else errorReplayAttack();

                } else errorMITM();
            }
            if (p.request == ChatRequest.RESPONSE && p.success.equals("access_denied")) {
                byte[] hashMessage = Encryption.generateSHA256Digest(p.success.getBytes("UTF-8") );
                if (Encryption.verifySignature(p.signature,hashMessage ,rsaPublicKeyServer)) {

                    System.out.println("ERROR LOGIN account client");
                    reset();
                }

            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGIN")) {


                byte[] hashMessage = Encryption.generateSHA256Digest(p.success.getBytes("UTF-8") );

                if (Encryption.verifySignature(p.signature,hashMessage ,rsaPublicKeyServer)) {

                    // This indicates a successful login
                    curUser = p.uid;
                    // This indicates a successful login and no man in the middle attack
                    //we are talking to the server
                    Authenticated = true;

                    //todo load chat and refresh after DH exchange success
                    loadChat();
                    RefreshList();

                    //start DH exchange process
                    startKeyPair(curUser);


                } else {
                    errorMITM();
                }



            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGOUT")) {

                byte[] messageHash = Encryption.generateSHA256Digest(p.success.getBytes("UTF-8"));
                if(Encryption.verifySignature(p.signature, messageHash,rsaPublicKeyServer))
                {
                    // Logged out, save chat log and clear messages on the UI
                    SaveChatHistory();
                    reset();
                }

            }


        }  catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    private void errorReplayAttack() {
        //this is a second time this system has seen this client nonce
        System.out.println("client detect : WARNING REPLAY ATTACK!!");
        reset();
    }

    private void errorMITM() {
        System.out.println("CLIENT DETECT :MAN IN THE MIDDLE ATTACK");
        reset();
    }

    private void generateSharedSecretKey(byte[] publicKeyComplete) {
        try {

            //client private key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPairClient.getPrivate());

            //server public key
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            //byte[] serverPublicKey = Encryption.privateKeyDecryptionByte(p.data,rsaPrivateKey);

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyComplete);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            keyAgreement.doPhase(publicKey, true);

            //create shared AES symmetric key
            byte sharedSecret[] = keyAgreement.generateSecret();
            symmetricKeyAES = Encryption.generateAESKeyFromShareSecret(sharedSecret, Encryption.KeySize.KEY256);

            SECURED_MODE = true;


        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private void loadChat() {
        // Time to load the chatlog
        InputStream ins = null;
        JsonReader jsonReader;
        File f = new File(this.getChatLogPath());
        if (f.exists() && !f.isDirectory()) {

            //load chat
            try {
                ins = new FileInputStream(this.getChatLogPath());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            jsonReader = Json.createReader(ins);
            chatlog = jsonReader.readArray();

        } else {
            try {
                f.createNewFile();
                ins = new FileInputStream(this.getChatLogPath());
                chatlog = Json.createArrayBuilder().build();
            } catch (IOException e) {
                System.err.println("Chatlog file could not be created or opened.");
            }
        }
    }


    /**
     * Gives the path of the local chat history file (user-based)
     */

    private String getChatLogPath() {
        return "log/chatlog-" + curUser + ".json";
    }

    /**
     * Methods dealing with local processing
     */

    /**
     * This method saves the Json array storing the chat log back to file
     */
    public void SaveChatHistory() {
        if (curUser.equals(""))
            return;
        try {
            // The chatlog file is named after both the client and the user
            // logged in

            OutputStream out = new FileOutputStream(this.getChatLogPath());
            JsonWriter writer = Json.createWriter(out);
            writer.writeArray(chatlog);
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }
    /**
     * Similar to the one in MyChatServer, serializes and send the Java object
     *
     * @param p ChatPacket to serialize and send
     */
    private void SerializeNSend(ChatPacket p) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(os);
            out.writeObject(p);
            byte[] packet = os.toByteArray();

            if(Authenticated && SECURED_MODE && p.request !=ChatRequest.IV)
            {
                packet = Encryption.encryptWithAES(packet,symmetricKeyAES, sendIV);
            }

            SendtoServer(packet);
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
     * Adds a message to the internal's client state
     *
     * @param from From whom the message comes from
     * @param to   To whom the messaged is addressed
     * @param buf  Message
     */
    private void Add1Message(String from, String to, byte[] buf) {
        JsonArrayBuilder builder = Json.createArrayBuilder();
        for (int i = 0; i < chatlog.size(); i++) {
            builder.add(chatlog.getJsonObject(i));
        }
        try {
            builder.add(Json.createObjectBuilder().add("from", from).add("to", to).add("time", "").add("message",
                    new String(buf, "UTF-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        JsonArray newl = builder.build();
        chatlog = newl;
        RefreshList();

    }

    /**
     * Generate client key pair
     * send
     *
     * @param uid
     */
    //Diffie-Hellman key agreement
    public void startKeyPair(String uid) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);

            keyPairClient = kpg.generateKeyPair();
            byte[] clientPublicKeyPair = keyPairClient.getPublic().getEncoded();

            //send public key to server
            ChatPacket newMSG = new ChatPacket();
            newMSG.request = ChatRequest.DH_PUBLIC_KEY;
            newMSG.uid = uid;
            newMSG.data = clientPublicKeyPair;
            byte[] messageHash = Encryption.generateSHA256Digest(newMSG.data);
            newMSG.signature = Encryption.generateSignature(messageHash,rsaPrivateKey);
            System.out.println("client send public key");

            SerializeNSend(newMSG);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



    /**
     * reset all information and clear the ui
     */
    private void reset() {
        curUser = "";
        UpdateMessages(null);
        Authenticated = false;
        SECURED_MODE =false;
        symmetricKeyAES = null;
    }

}
