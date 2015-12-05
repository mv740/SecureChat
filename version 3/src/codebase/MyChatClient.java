package codebase;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
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

    private String password = null;
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



    MyChatClient(boolean IsA) {


        // This is the minimum constructor you must
        // preserve
        super(IsA); // IsA indicates whether it's client A or B
        startComm(); // starts the communication
        rsaPublicKeyServer = Encryption.rsaLoadPublicKey(new File("./certificate/server.crt"));

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
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.LOGIN;
        p.uid = uid;

        if (!Authenticated) {
            this.uid = uid;
            System.out.println("client ask for server nonce");
            getNonce(uid);
        } else
            SerializeNSend(p);
    }


    //ask a nonce from the server
    public void getNonce(String uid) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.Nonce;
        p.uid = uid;

        p.rsaPublicKey = rsaPublicKey; //send her public key to server
        p.cnonce = Encryption.publicKeyEncryption(Encryption.generateNonce(), rsaPublicKeyServer); //create client nonce and encrypt it
        p.signature = Encryption.generateSignature((p.rsaPublicKey).getEncoded(), rsaPrivateKey); //we prove that we are the one sending this message

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
        rsaPrivateKey = Encryption.rsaLoadPrivateKey(path);
    }

    /**
     * Callback invoked when an authentication mode is selected.
     *
     * @param IsPWD True if password-based (false if certificate-based).
     */
    public void ReceivedMode(boolean IsPWD) {
        // TODO
        if (!IsPWD) {
            //load certificate
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


            in = new ObjectInputStream(is);
            Object o = in.readObject();
            p = (ChatPacket) o;

            if(Authenticated)
            {
                if(p.request == ChatRequest.DH_PUBLIC_KEY)
                {
                    System.out.println("client receive public from server");
                    generateSharedSecretKey(p);
                }
            }

            if (p.request == ChatRequest.Nonce) {

                System.out.println("client receive server nonce from server");

                //verify that we are receiving from the real server
                if (Encryption.verifySignature(p.signature, p.cnonce, rsaPublicKeyServer)) {

                    if (clientNonce != p.cnonce) {
                        //store it to check for future  authentication
                        clientNonce = p.cnonce;
                        //client nonce can never be reused
                        // passed nonce challenge,


                        //server still need to authenticate us
                        ChatPacket loginMsg = new ChatPacket();
                        System.out.println("client send back the server nonce");
                        loginMsg.request = ChatRequest.LOGIN;
                        loginMsg.uid = this.uid;
                        System.out.println("client uid: " + this.uid);
                        loginMsg.snonce = Encryption.privateKeyDecryptionByte(p.snonce, rsaPrivateKey);
                        loginMsg.signature = Encryption.generateSignature(loginMsg.snonce, rsaPrivateKey); //sign bob's challenge
                        SerializeNSend(loginMsg);

                    } else {
                        //this is a second time this system has seen this client nonce
                        System.out.println("client side : WARNING REPLAY ATTACK!!");

                    }

                } else {
                    System.out.println("Client side : WARNING MAN IN THE MIDDLE ATTACK");

                }


            }
            if (p.request == ChatRequest.RESPONSE && p.success.equals("access_denied")) {
                //System.out.println("ERROR LOGIN account client");
                reset();
                Authenticated = false;
            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGIN")) {

                if (Encryption.verifySignature(p.signature,p.success.getBytes("UTF-8") ,rsaPublicKeyServer)) {

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
                    System.out.println("DANGER : we got are talking to somebuddy else");
                    Authenticated = false;

                }



            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGOUT")) {
                // Logged out, save chat log and clear messages on the UI
                SaveChatHistory();
                reset();
                Authenticated = false;
            } else if (p.request == ChatRequest.CHAT && !curUser.equals("")) {
                // A new chat message received
                Add1Message(p.uid, curUser, p.data);
            } else if (p.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
                // This was sent by us and now it's confirmed by the server, add
                // it to chat history
                Add1Message(curUser, p.uid, p.data);
            }


        }  catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    private void generateSharedSecretKey(ChatPacket p) {
        try {

            //client private key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPairClient.getPrivate());

            //server public key
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            byte[] serverPublicKey = Encryption.privateKeyDecryptionByte(p.data,rsaPrivateKey);

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            keyAgreement.doPhase(publicKey, true);

            //create shared AES symmetric key
            byte sharedSecret[] = keyAgreement.generateSecret();
            System.out.println("client shared key size" +sharedSecret.length);
            symmetricKeyAES = Encryption.generateAESKey(sharedSecret);

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

            if(Authenticated && SECURED_MODE)
            {
                packet = Encryption.AESencrypt(packet,symmetricKeyAES);
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
            kpg.initialize(512); //todo 1024 bit ...  now with 512 it create a 227 byte

            keyPairClient = kpg.generateKeyPair();
            DHParameterSpec dhSpec = ((DHPublicKey) keyPairClient.getPublic()).getParams();
            BigInteger clientG = dhSpec.getG();
            BigInteger clientP = dhSpec.getP();
            int clientL = dhSpec.getL();

            System.out.println(keyPairClient.getPublic().getEncoded().length);
            System.out.println(keyPairClient.getPrivate().getEncoded().length);
            byte[] clientPublicKeyPair = keyPairClient.getPublic().getEncoded();

            System.out.println("client public key size DH => " +clientPublicKeyPair.length);
            System.out.println("client public key size DH => " + Arrays.toString(keyPairClient.getPublic().getEncoded()));

            //send public key to server
            ChatPacket newMSG = new ChatPacket();
            newMSG.request = ChatRequest.DH_PUBLIC_KEY;
            newMSG.uid = uid;
            newMSG.data = Encryption.publicKeyEncryption(clientPublicKeyPair,rsaPublicKeyServer);
            //newMSG.signature = Encryption.generateSignature(uid.getBytes("UTF-8"),rsaPrivateKey);
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
    }

}
