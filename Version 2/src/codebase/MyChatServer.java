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
import java.util.Arrays;
import java.util.Objects;

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
    private boolean[] Authenticated;


    //server nonce store
    private byte[][] serverNonce;
    private byte[][] clientNonce;

    // In Constructor, the user database is loaded.
    MyChatServer() {
        try {
            InputStream in = new FileInputStream("database.json");
            JsonReader jsonReader = Json.createReader(in);
            database = jsonReader.readArray();
            Authenticated = new boolean[2];
            serverNonce = new byte[2][];
            clientNonce = new byte[2][];


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


        try {
            ChatPacket p = null;

            //accept chat message/or logout from authenticated user only
            if (Authenticated[getUser(IsA)]) {
                in = new ObjectInputStream(is);
                Object o = in.readObject();
                p = (ChatPacket) o;

                if (p.request == ChatRequest.LOGOUT) {
                    if (IsA) {
                        statA = "";
                    } else {
                        statB = "";
                    }
                    UpdateLogin(IsA, "");
                    RespondtoClient(IsA, "LOGOUT", null);
                    authenticatedConnectionStop(IsA);


                } else if (p.request == ChatRequest.CHAT) {
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
                }
            } else {
                in = new ObjectInputStream(is);
                Object o = in.readObject();
                p = (ChatPacket) o;

                if (p.request == ChatRequest.Nonce) {
                    System.out.println("create server nonce");

                    serverNonce[getUser(IsA)] = Encryption.generateNonce();
                    //send to client
                    ChatPacket msg = new ChatPacket();
                    msg.request = ChatRequest.Nonce;
                    msg.uid = IsA ? statA : statB;
                    msg.success = "Success";
                    msg.data = serverNonce[getUser(IsA)];
                    //System.out.println("server send Nonce " + (Arrays.toString(msg.data)));
                    SerializeNSend(IsA, msg);


                }
                if (p.request == ChatRequest.LOGIN) {
                    // We want to go through all records
                    System.out.println("server receive client hashed");
                    for (int i = 0; i < database.size(); i++) {


                        JsonObject l = database.getJsonObject(i);

                        String clientPassword = l.getString("password");
                        byte[] serverHash = new byte[0];

                        boolean UniqueNonce = false;

                        //clientNounceReceivedLog(p);
                        if (Objects.equals(Arrays.toString(clientNonce[getUser(IsA)]), Arrays.toString(p.cnonce))) {
                            //man in the middle attack, he is trying to replay attack
                            //that cnonce was already used once !!!! WARNING
                            this.UpdateServerLog("MAN in the middle ATTACK Detected!");

                        } else {
                            UniqueNonce = true;
                            serverHash = Encryption.generateHash(p.cnonce, serverNonce[getUser(IsA)], clientPassword);
                        }
                        if (UniqueNonce) {
                            if (l.getString("uid").equals(p.uid) && Objects.equals(Arrays.toString(serverHash), Arrays.toString(p.data))) {

                                // We do not allow one user to be logged in on multiple
                                // clients
                                if (p.uid.equals(IsA ? statB : statA))
                                    continue;

                                //store unique
                                clientNonce[getUser(IsA)] = p.cnonce;

                                //hash match
                                this.UpdateServerLog("is Alice user :" + IsA + " is really that person ! and authenticated ");
                                System.out.println("Authenticated USER");
                                // Authenticated[getUser(IsA)] = true;
                                authenticatedConnectionStart(IsA);

                                // Update the corresponding login status
                                if (IsA) {
                                    statA = l.getString("uid");
                                } else {
                                    statB = l.getString("uid");
                                }

                                // Update the UI to indicate this
                                UpdateLogin(IsA, l.getString("uid"));

                                // Inform the client that it was successful
                                System.out.println("server sucessful login");
                                RespondtoClient(IsA, "LOGIN", serverHash);

                                break;

                            } else if(l.getString("uid").equals(p.uid)) {
                                //checking uid because we are looping through the database. if you are alice you find password in 1 loop
                                // bob will need 2, because 1 loop will not match
                                //we only considered a login error if you are the specific user and
                                // we find your password in the database but it didn't match to the hash you send

                                System.out.println("error login");
                                this.UpdateServerLog("error login from user IsA" + IsA);
                            }
                        }


                    }

                    if ((IsA ? statA : statB).equals("")) {
                        // Oops, this means a failure, we tell the client so
                        System.out.println("SYSTEM DENIED ACCESS");
                        RespondtoClient(IsA, "access_denied", null);
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
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
    void RespondtoClient(boolean IsA, String Success, byte[] validation) {
        ChatPacket p = new ChatPacket();
        p.request = ChatRequest.RESPONSE;
        p.uid = IsA ? statA : statB;
        p.success = Success;
        p.data = validation;

        SerializeNSend(IsA, p);
    }

    private void authenticatedConnectionStart(Boolean IsA) {
        if (IsA) {
            this.UpdateServerLog("server initiate authenticated connection with alice");
        } else
            this.UpdateServerLog("server initiate authenticated connection with Bob");
        Authenticated[getUser(IsA)] = true;
    }


    private void authenticatedConnectionStop(Boolean IsA) {
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

