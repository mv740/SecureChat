package codebase;

import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
    private byte[] serverNonceA;
    private byte[] serverNonceB;
    private byte[] clientNonceA;
    private byte[] clientNonceB;

    //clients Public keys
    RSAPublicKey rsaPublicKeyAlice;
    RSAPublicKey rsaPublicKeyBob;

    //server PrivateKey
    RSAPrivateKey rsaPrivateKeyServer;






    // In Constructor, the user database is loaded.
    MyChatServer() {
        try {
            InputStream in = new FileInputStream("database.json");
            JsonReader jsonReader = Json.createReader(in);
            database = jsonReader.readArray();
            Authenticated = new boolean[2];

            //URL url = getClass().getResource("ListStopWords.txt");
            //String workingDirectory = System.getProperty("certificate");
            //System.out.println(workingDirectory);


            //System.out.println((new File("./certificate/private/server.key.pem")));
            rsaPrivateKeyServer = Encryption.rsaLoadPrivateKey((new File("./certificate/private/server.key.pem")));
            System.out.println("key"+rsaPrivateKeyServer.getModulus().bitLength());
            rsaPublicKeyAlice = Encryption.rsaLoadPublicKey(new File("./certificate/alice.crt"));
            System.out.println("key"+rsaPublicKeyAlice.getModulus().bitLength());
            rsaPublicKeyBob = Encryption.rsaLoadPublicKey(new File("./certificate/bob.crt"));


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
        System.out.println(buf.length);
        //WTF IS GOING HERE
        //buf = Arrays.copyOfRange(buf,0, 256);
        System.out.println("2-ENCRYPTED =>"+Arrays.toString(buf));
        System.out.println("size "+buf.length);

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
                    securedConnectionStop(IsA);


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

                ObjectInput objectInput = new ObjectInputStream(is);
                Object object = objectInput.readObject();
                p = (ChatPacket) object;


                //p = Encryption.PrivateKeyDecryption1(is, rsaPrivateKeyServer);
                System.out.println("IT WORK uid=" +p.uid);




                if (p.request == ChatRequest.Nonce) {
                    System.out.println("create server nonce");


                    if(Encryption.verifySignature(p.signature,(p.uid).getBytes("UTF-8"),(IsA ? rsaPublicKeyAlice: rsaPublicKeyBob) ));
                    {
                        System.out.println("VALID SIGNATURE");
                    }

                    if (IsA) {
                        serverNonceA = Encryption.generateNonce();
                    } else {
                        serverNonceB = Encryption.generateNonce();
                    }

                    //send to client
                    ChatPacket msg = new ChatPacket();
                    msg.request = ChatRequest.Nonce;
                    //msg.uid = IsA ? statA : statB;
                    //msg.success = "ok";
                    msg.data = IsA ? serverNonceA : serverNonceB;
                    System.out.println("server send Nonce " + (Arrays.toString(msg.data)));
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
                        if (IsA) {

                            clientNounceReceivedLog(p);
                            if (Objects.equals(Arrays.toString(clientNonceA), Arrays.toString(p.cnonce))) {
                                //man in the middle attack, he is trying to replay attack
                                //that cnonce was already used once !!!! WARNING
                                this.UpdateServerLog("MAN in the middle ATTACK Detected!");

                            } else {
                                UniqueNonce = true;
                                serverHash = Encryption.generateHash(p.cnonce, serverNonceA, clientPassword);
                            }

                        } else {
                            clientNounceReceivedLog(p);
                            if (Objects.equals(Arrays.toString(clientNonceB), Arrays.toString(p.cnonce))) {
                                //man in the middle attack, he is trying to replay attack
                                //that cnonce was already used once !!!! WARNING
                                this.UpdateServerLog("MAN in the middle ATTACK Detected!");

                            } else {
                                UniqueNonce = true;
                                serverHash = Encryption.generateHash(p.cnonce, serverNonceB, clientPassword);

                            }




                        }

                        if (UniqueNonce) {
                            //  //l.getString("uid").equals(p.uid)&& l.getString("password").equals(p.password)
                            if (l.getString("uid").equals(p.uid) && Objects.equals(Arrays.toString(serverHash), Arrays.toString(p.data))) {


                                //store unique
                                if(IsA)
                                    clientNonceA = p.cnonce;
                                else
                                    clientNonceB = p.cnonce;




                                //hash match
                                this.UpdateServerLog("is Alice user :" + IsA + " is really that person ! and authenticated ");
                                System.out.println("Authenticated USER");
                                Authenticated[getUser(IsA)] = true;
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
                                System.out.println("server sucessful login");
                                RespondtoClient(IsA, "LOGIN", serverHash);

                                break;

                            } else {
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

            System.out.println("server send packet size b4 encrypt: "+packet.length);
            //if alice, use her public key if not user bob's public key
            packet = Encryption.PublicKeyEncryption(packet,IsA ? rsaPublicKeyAlice : rsaPublicKeyBob);

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

