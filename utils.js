import { Keypair, TextEncoder } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import jwt from "jsonwebtoken";

// Signing a transaction using a secret key
export const signTransaction = (pk) => {
    const keypair = Keypair.fromSecretKey(bs58.decode(pk));
    const timestamp = Date.now().toString();
    const message = new TextEncoder().encode(`Sign in to pump.fun: ${timestamp}`);

    // Sign the transaction
    const signature = nacl.sign.detached(message, keypair.secretKey);

    // Encode the signature in base58
    return bs58.encode(signature);
};

// Create a new wallet
const createWallet = () => {
    // Generate a new random keypair
    const newKeypair = Keypair.generate();

    const publicKey = newKeypair.publicKey.toBase58();
    const secretKey = [...newKeypair.secretKey];
    const secretKeyBase58 = bs58.encode(Uint8Array.from(secretKey));

    const walletData = {
        publicKey: publicKey,
        secretKey: secretKey,
        secretKeyBase58: secretKeyBase58
    };

    return walletData;
};

// Create multiple wallets
export const createWallets = (amt) =>
    Promise.all(Array.from({ length: amt }, () => createWallet().publicKey.toBase58()));

// Generate a JWT token for authentication
export const generateJwtToken = (address) => {
    const secretKey = process.env.JWT_SECRET || "your_jwt_secret_key"; // Add your JWT secret in environment variables
    const token = jwt.sign({ address }, secretKey, { expiresIn: '1h' });
    return token;
};

// Verify JWT Token
export const verifyJwt = (token) => {
    const secretKey = process.env.JWT_SECRET || "your_jwt_secret_key"; // Add your JWT secret in environment variables
    try {
        const decoded = jwt.verify(token.split(' ')[1], secretKey); // Assumes 'Bearer <token>' format
        return decoded; // Contains the decoded payload (e.g., address)
    } catch (error) {
        return null; // Invalid token
    }
};

// Example of validating a signature (custom logic here)
export const validateSignature = (address, signature) => {
    // Implement your logic to validate the signature and address
    return true; // Placeholder: You should add real validation logic
};
