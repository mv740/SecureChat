package codebase;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.*;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.json.stream.JsonParsingException;

import com.sun.xml.internal.ws.api.message.Packet;
import infrastructure.ChatClient;
import org.apache.commons.ssl.PKCS8Key;

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
    private byte[] clienthash;
    private SecretKey LogKey;

    //certificates Public/Private
    RSAPublicKey rsaPublicKey;
    RSAPrivateKey rsaPrivateKey;

    //server publicKey
    RSAPublicKey rsaPublicKeyServer;


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


    public void getNonce(String uid) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.Nonce;
        p.uid = uid;

        try {

            p.signature = Encryption.generateSignature((p.uid).getBytes("UTF-8"),rsaPrivateKey); //sign uid

            //System.out.println("signature size "+p.signature.length);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

//        byte[] encrypted=null;
//        try {
//            encrypted = Encryption.PublicKeyEncryption(s.getBytes("UTF-8"), rsaPublicKeyServer);
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//
//        System.out.println("TESTING :"+Arrays.toString(encrypted));
//        p.testing = encrypted;

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
        if(Authenticated)
        {
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

            if (p.request == ChatRequest.Nonce) {

                System.out.println("client receive nonce from server");

                clientNonce = Encryption.generateNonce();
                byte[] serverNonce = p.data;
                //hash(cnonce+nonce+password
                System.out.println("server once received:" + Arrays.toString(p.data));
                clienthash = Encryption.generateHash(clientNonce, serverNonce, password);

                //try to authenticated
                ChatPacket loginMsg = new ChatPacket();
                System.out.println("client nonce send "+clientNonce.length);
                loginMsg.request = ChatRequest.LOGIN;
                loginMsg.uid = this.uid;
                loginMsg.data = clienthash;
                loginMsg.cnonce = clientNonce;
                System.out.println("client nonce +" +Arrays.toString(clientNonce));
                System.out.println("client send hashed password+cnonce+nonce");
                SerializeNSend(loginMsg);


            }
            if (p.request == ChatRequest.RESPONSE && p.success.equals("access_denied")) {
                //System.out.println("ERROR LOGIN account client");
                reset();
                Authenticated = false;
            } else if (p.request == ChatRequest.RESPONSE && p.success.equals("LOGIN")) {
                // This indicates a successful login
                curUser = p.uid;

                if (Objects.equals(Arrays.toString(clienthash), Arrays.toString(p.data))) {
                    // This indicates a successful login and no man in the middle attack
                    //we are talking to the server
                    Authenticated = true;
                }
                else
                {
                    System.out.println("we got are talking to somebuddy else");
                    Authenticated = false;

                }

                // Time to load the chatlog
                InputStream ins = null;
                JsonReader jsonReader;
                File f = new File(this.getChatLogPath());
                if (f.exists() && !f.isDirectory()) {

                    // log file are encrypted using a unique identifer created from local user's hard disk serial number
                    // to decrypt it, you will need you physically own  the hard disk
                    //http://superuser.com/questions/498083/how-to-get-hard-drive-serial-number-from-command-line
                    String uniqueHostIdentifier = getDiskSerialNumber();
                    LogKey = Encryption.generateKey(uniqueHostIdentifier.getBytes("UTF-8"));


                    //ins = new FileInputStream(this.getChatLogPath());
                    try {
                        //first time program is run, log is still not encrypted
                        ins = new FileInputStream(this.getChatLogPath());
                        jsonReader = Json.createReader(ins);
                        chatlog = jsonReader.readArray();
                    } catch (JsonParsingException e) {
                        System.out.println("encrypted log files detected");

                        byte[] iv = Encryption.retrieveIV(this.getChatLogPath());
                        ins = Encryption.decryptStream(this.getChatLogPath(), LogKey, iv);
                        jsonReader = Json.createReader(ins);
                        chatlog = jsonReader.readArray();

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
                reset();
                Authenticated =false;
            } else if (p.request == ChatRequest.CHAT && !curUser.equals("")) {
                // A new chat message received
                Add1Message(p.uid, curUser, p.data);
            } else if (p.request == ChatRequest.CHAT_ACK && !curUser.equals("")) {
                // This was sent by us and now it's confirmed by the server, add
                // it to chat history
                Add1Message(curUser, p.uid, p.data);
            }


        } catch (FileNotFoundException e) {
            e.printStackTrace();
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
        // The chatlog file is named after both the client and the user
        // logged in


        //OutputStream out = new FileOutputStream(this.getChatLogPath());
        byte[] iv = Encryption.generateIV();
        //System.out.println("created IV "+Arrays.toString(iv));
        OutputStream out = Encryption.encryptStream(this.getChatLogPath(), LogKey,iv);
        JsonWriter writer = Json.createWriter(out);
        writer.writeArray(chatlog);
        writer.close();

        //store iv to file
        Encryption.storeIV(iv,this.getChatLogPath());

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
            //SendtoServer(packet);

            System.out.println("packet size "+packet.length);
            //byte[] tosend = Encryption.PublicKeyEncryption(packet, rsaPublicKeyServer);

            //System.out.println("1-ENCRYPTED =>"+Arrays.toString(tosend));
            //RSAPrivateKey rsaPrivateKeyServer = Encryption.rsaLoadPrivateKey((new File("./certificate/private/server.key.pem")));
            //byte[] test = Encryption.PublicKeyDecryption(packet,rsaPrivateKeyServer);
            //System.out.println(""+Arrays.toString(test));

            //System.out.println("packet size : "+packet.length);
            //System.out.println(tosend.length);
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
     * Enable to execute shell command from java
     * <p>
     * //http://www.mkyong.com/java/how-to-execute-shell-command-from-java/
     *
     * @param command shell command
     * @return output of your command
     */
    private String executeCommand(String command) {

        StringBuffer output = new StringBuffer();

        java.lang.Process p;
        try {
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line); //removed the "\n"
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return output.toString();

    }

    /**
     * get the local user's hard disk serial number!
     * This is unique because there can't be two hard disk with the same serial number
     *
     * @return serial number
     */
    private String getDiskSerialNumber() {
        //wmic diskdrive get serialnumber
        String queryResult = executeCommand("wmic diskdrive get serialnumber");
        //ignore SerialNumber word
        System.out.println(queryResult);
        String result = queryResult.replaceAll("\\s", ""); //removed formating tab/whitespaces
        System.out.println(result);
        return result.substring("SerialNumber".length()); //removed this word

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
