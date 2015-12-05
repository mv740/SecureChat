package codebase;

/**
 * You can define all your supported request types here, depending on your chosen protocol.
 * Again, the few below may NOT be suitable for you.
 */
public enum ChatRequest {
    LOGIN,
    LOGOUT,
    CHAT,
    RESPONSE,
    CHAT_ACK,
    DH_PUBLIC_KEY,
    Nonce,
    IV
}
