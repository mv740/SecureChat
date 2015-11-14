package codebase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import infrastructure.ChatServer;

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

    //keys
    private Boolean SECURED_MODE = false;
    private SecretKey symmetricKeyAES;
    private SecretKey[] symmetricKeyStore;

    // In Constructor, the user database is loaded.
    MyChatServer() {
        try {
            InputStream in = new FileInputStream("database.json");
            JsonReader jsonReader = Json.createReader(in);
            database = jsonReader.readArray();

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
        ByteArrayInputStream is = new ByteArrayInputStream(buf);
        ObjectInput in = null;

        //http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex
        //http://docstore.mik.ua/orelly/java-ent/security/ch13_07.htm
        //todo "is" that packet is encrypted, we need to decrypt it before being able to parse it to a object
//        if (SECURED_MODE) {
//            //for testing
//            System.out.println("encryption packet detected");
//            ChatPacket hello = AES.decrypt(is, symmetricKeyAES);
//            System.out.println(hello.password);
//
//
//        }

        try {
            ChatPacket p;


            if (SECURED_MODE) {
                p = AES.decrypt(is, symmetricKeyAES);

                if (p.request == ChatRequest.LOGIN) {
                    // We want to go through all records
                    for (int i = 0; i < database.size(); i++) {

                        JsonObject l = database.getJsonObject(i);

                        // When both uid and pwd match
                        if (l.getString("uid").equals(p.uid)
                                && l.getString("password").equals(p.password)) {
                            System.out.println("Authenticated USER");
                            // We do not allow one user to be logged in on multiple
                            // clients
                            if (p.uid.equals(IsA ? statB : statA))
                                continue;

                            // Update the corresponding login status
                            if (IsA) {
                                statA = l.getString("uid");
                            } else {
                                statB = l.getString("uid");
                            }

                            // Update the UI to indicate this
                            UpdateLogin(IsA, l.getString("uid"));

                            // Inform the client that it was successful
                            RespondtoClient(IsA, "LOGIN");

                            break;
                        }

                    }

                    if ((IsA ? statA : statB).equals("")) {
                        // Oops, this means a failure, we tell the client so
                        RespondtoClient(IsA, "");
                    }
                } else if (p.request == ChatRequest.LOGOUT) {
                    if (IsA) {
                        statA = "";
                    } else {
                        statB = "";
                    }
                    SECURED_MODE = false;
                    symmetricKeyAES = null;
                    UpdateLogin(IsA, "");
                    RespondtoClient(IsA, "LOGOUT");

                } else if (p.request == ChatRequest.CHAT) {
                    // This is a chat message

                    // Whoever is sending it must be already logged in
                    if ((IsA && statA != "") || (!IsA && statB != "")) {
                        // Forward the original packet to the recipient
                        SendtoClient(!IsA, buf);
                        p.request = ChatRequest.CHAT_ACK;
                        p.uid = (IsA ? statB : statA);

                        // Flip the uid and send it back to the sender for updating
                        // chat history
                        SerializeNSend(IsA, p);
                    }
                }
            } else {
                in = new ObjectInputStream(is);
                Object o = in.readObject();
                p = (ChatPacket) o;

                if (p.request == ChatRequest.DH_PUBLIC_KEY) {
                    System.out.println("server start create public key");
                    try {


                        //used parameters send by client
                        byte[] clientPublicKeyPair = p.data;

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

                            System.out.println("server create secret key");
                            //create shared secret KEY
                            serverKeyAgreement.doPhase(clientPubKey, true);
                            byte[] sharedSecret = serverKeyAgreement.generateSecret();

                            //create AES key
                            symmetricKeyAES = AES.generateKey(sharedSecret);
                           // symmetricKeyStore[(p.uid)] = symmetricKeyAES;


                            //server encode his public key and send to client
                            byte[] serverPublicKey = serverKeyPair.getPublic().getEncoded();

                            //send to client
                            ChatPacket msg = new ChatPacket();
                            msg.request = ChatRequest.DH_PUBLIC_KEY;
                            msg.uid = IsA ? statA : statB;
                            msg.success = "Success";
                            msg.data = serverPublicKey;

                            System.out.println("server send server public key");
                            SerializeNSend(IsA, msg);


                        } catch (InvalidAlgorithmParameterException e) {
                            e.printStackTrace();
                        }

                    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
                        e.printStackTrace();
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

        //ChatRequest test = p.request;

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            out = new ObjectOutputStream(os);
            out.writeObject(p);
            byte[] packet = os.toByteArray();

            if(SECURED_MODE)
            {
                System.out.println("SEND SERVER SECURED MSG");
                packet = AES.encrypt(packet,symmetricKeyAES);
            }
            SendtoClient(IsA, packet);

            if(p.request == ChatRequest.DH_PUBLIC_KEY)
            {
                System.out.println("ACTIVATE ENCRYPTION ");
                SECURED_MODE = true;
            }


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
    void RespondtoClient(boolean IsA, String Success) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.RESPONSE;
        p.uid = IsA ? statA : statB;
        p.success = Success;

        SerializeNSend(IsA, p);
    }

}
