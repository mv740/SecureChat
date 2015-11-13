package codebase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import com.sun.crypto.provider.AESKeyGenerator;
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

    private PublicKey serverPublicKey = null;
    private KeyPair keyPairClient = null;
    private SecretKey DesSecretKey = null;
    private String password = null;
    private String uid = null;
    private Boolean SECURED_MODE = false;


    MyChatClient(boolean IsA) { // This is the minimum constructor you must
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
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.LOGIN;
        p.uid = uid;
        p.password = pwd;

        if (pwd.length()>0) {
            this.uid = uid;
            this.password = pwd;
            startKeyPair(uid, pwd);
        } else
            SerializeNSend(p);
    }

    /**
     * Generate client key pair
     * send
     *
     * @param uid
     */
    //Diffie-Hellman key agreement
    public void startKeyPair(String uid, String pwd) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(1024);

            keyPairClient = kpg.generateKeyPair();
            DHParameterSpec dhSpec = ((DHPublicKey) keyPairClient.getPublic()).getParams();
            BigInteger clientG = dhSpec.getG();
            BigInteger clientP = dhSpec.getP();
            int clientL = dhSpec.getL();

            byte[] clientPublicKeyPair = keyPairClient.getPublic().getEncoded();


            //send public key to server
            ChatPacket newMSG = new ChatPacket();
            newMSG.request = ChatRequest.DH_PUBLIC_KEY;
            newMSG.uid = uid;
            newMSG.data = clientPublicKeyPair;
            System.out.println("client send public key");
            SerializeNSend(newMSG);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    /**
     * Callback invoked when the certificate file is selected
     *
     * @param path Selected certificate file's path
     */
    public void FileLocationReceivedCert(File path) {
        // TODO
    }

    /**
     * Callback invoked when the private key file is selected
     *
     * @param path Selected private key file's path
     */
    public void FileLocationReceivedPriv(File path) {
        // TODO
    }

    /**
     * Callback invoked when an authentication mode is selected.
     *
     * @param IsPWD True if password-based (false if certificate-based).
     */
    public void ReceivedMode(boolean IsPWD) {
        // TODO
        if (IsPWD) {

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
        SerializeNSend(p);
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
        try {
            in = new ObjectInputStream(is);
            Object o = in.readObject();
            ChatPacket p = (ChatPacket) o;


            if (p.request == ChatRequest.DH_PUBLIC_KEY) {
                try {
                    System.out.println("client receive public from server");

                    //client private key
                    KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                    keyAgreement.init(keyPairClient.getPrivate());

                    //server public key
                    KeyFactory keyFactory = KeyFactory.getInstance("DH");
                    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(p.data);
                    PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
                    keyAgreement.doPhase(publicKey, true);

                    //create secret key
                    //SecretKey secretKey = keyAgreement.generateSecret("AES");
                    byte sharedSecret[] = keyAgreement.generateSecret();


                    //des key
                    SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
                    DESKeySpec desSpec = new DESKeySpec(sharedSecret);
                    DesSecretKey = skf.generateSecret(desSpec);

                    //try to login with password
                    ChatPacket loginMsg = new ChatPacket();
                    loginMsg.request = ChatRequest.LOGIN;
                    loginMsg.uid = this.uid;
                    loginMsg.password = this.password;

                    SECURED_MODE = true;
                    SerializeNSend(loginMsg);


                } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                    e.printStackTrace();
                }
            }

            if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGIN")) {
                // This indicates a successful login
                curUser = p.uid;

                // Time to load the chatlog
                InputStream ins = null;
                JsonReader jsonReader;
                File f = new File(this.getChatLogPath());
                if (f.exists() && !f.isDirectory()) {
                    try {
                        ins = new FileInputStream(this.getChatLogPath());
                        jsonReader = Json.createReader(ins);
                        chatlog = jsonReader.readArray();
                    } catch (FileNotFoundException e) {
                        System.err.println("Chatlog file could not be opened.");
                    }
                } else {
                    try {
                        f.createNewFile();
                        ins = new FileInputStream(this.getChatLogPath());
                        chatlog = Json.createArrayBuilder().build();
                    } catch (IOException e) {
                        System.err.println("Chatlog file could not be created or opened.");
                    }
                }

                RefreshList();

            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGOUT")) {
                // Logged out, save chat log and clear messages on the UI
                SaveChatHistory();
                curUser = "";
                UpdateMessages(null);
            } else if (p.request == ChatRequest.CHAT && !curUser.equals("")) {
                // A new chat message received
                Add1Message(p.uid, curUser, p.data);
            } else if (p.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
                // This was sent by us and now it's confirmed by the server, add
                // it to chat history
                Add1Message(curUser, p.uid, p.data);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
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
            SealedObject sealedObject = null;

            if (SECURED_MODE) {
                try {

                    //encrypt
                    Cipher c = Cipher.getInstance("DES");
                    c.init(Cipher.ENCRYPT_MODE, DesSecretKey);
                    byte[] encrypted = c.doFinal(packet);
                    sealedObject = new SealedObject(packet,c);
                    packet = encrypted;

                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }catch (InvalidKeyException e) {
                    e.printStackTrace();
                }catch (BadPaddingException e){
                    e.printStackTrace();
                }catch (IllegalBlockSizeException e)
                {
                    e.printStackTrace();
                }


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


}
