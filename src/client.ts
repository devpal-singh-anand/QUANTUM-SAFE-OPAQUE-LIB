import { getLeap } from './leap-wrapper.js';
import { keyGen, encapsulate } from './mlkem.js';
import { hkdf, hmac, verifyHmac, transcriptHash, deriveFinalKey } from './keyschedule.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ClientRegisterRequest {
    username: string;
    blind: Uint8Array;
}

export interface ClientRegisterFinish {
    username: string;
    envelope: Uint8Array;       // encrypted + authenticated credential envelope
    mlkemPublicKey: Uint8Array; // client's ML-KEM public key
}

export interface ServerRegisterResponse {
    evaluated: Uint8Array;
}

export interface ClientLoginRequest {
    username: string;
    blind: Uint8Array;
}

export interface ServerLoginResponse {
    evaluated: Uint8Array;
    envelope: Uint8Array;
    mlkemPublicKey: Uint8Array; // server's ML-KEM public key
}

export interface ClientLoginFinish {
    username: string;
    mlkemCiphertext: Uint8Array;
    clientMac: Uint8Array;
}

export interface ServerLoginConfirm {
    serverMac: Uint8Array;
}

export interface LoginResult {
    sessionKey: Uint8Array;
}

// ── Client ───────────────────────────────────────────────────────────────────

export class QHOpaqueClient {

    // ── Registration ────────────────────────────────────────────────────────

    async startRegister(
        username: string,
        password: string
    ): Promise<{ request: ClientRegisterRequest; clientState: Uint8Array }> {
        const leap = await getLeap();
        const { blind, clientState } = leap.blind(password);
        return {
            request: { username, blind },
            clientState,
        };
    }

    async finishRegister(
        password: string,
        clientState: Uint8Array,
        serverResponse: ServerRegisterResponse
    ): Promise<ClientRegisterFinish> {
        const leap = await getLeap();

        // Unblind to get the OPRF output
        const oprfOut = leap.unblind(serverResponse.evaluated, clientState);

        // Derive envelope key from OPRF output
        const envelopeKey = hkdf(oprfOut, 'qh-opaque-envelope-key', 32);

        // Generate client's ML-KEM key pair
        const { publicKey, secretKey } = await keyGen();

        // Envelope = encrypt(secretKey) with envelopeKey using AES-256-GCM
        const envelope = await encryptEnvelope(envelopeKey, secretKey);

        return {
            username: '',   // caller fills this in
            envelope,
            mlkemPublicKey: publicKey,
        };
    }

    // ── Login ────────────────────────────────────────────────────────────────

    async startLogin(
        username: string,
        password: string
    ): Promise<{ request: ClientLoginRequest; clientState: Uint8Array }> {
        const leap = await getLeap();
        const { blind, clientState } = leap.blind(password);
        return {
            request: { username, blind },
            clientState,
        };
    }

    async finishLogin(
        password: string,
        clientState: Uint8Array,
        serverResponse: ServerLoginResponse
    ): Promise<{ finish: ClientLoginFinish; sessionKey: Uint8Array }> {
        const leap = await getLeap();

        // Unblind
        const oprfOut = leap.unblind(serverResponse.evaluated, clientState);

        // Derive envelope key and open envelope
        const envelopeKey = hkdf(oprfOut, 'qh-opaque-envelope-key', 32);
        const clientSecretKey = await decryptEnvelope(envelopeKey, serverResponse.envelope);
        // Wrong password → decryptEnvelope throws here, login fails closed

        // ML-KEM encapsulate against server's public key
        const { ciphertext, sharedSecret } = await encapsulate(serverResponse.mlkemPublicKey);

        // Transcript: blind + evaluated + ciphertext (in order)
        const transcript = transcriptHash([
            serverResponse.evaluated,
            ciphertext,
        ]);

        // Derive session keys
        const { sessionKey, clientMacKey, serverMacKey } = deriveFinalKey(sharedSecret, transcript);

        // Client confirmation MAC
        const clientMac = hmac(clientMacKey, transcript);

        return {
            finish: {
                username: '',   // caller fills this in
                mlkemCiphertext: ciphertext,
                clientMac,
            },
            sessionKey,
        };
    }

    async verifyServerMac(
        serverConfirm: ServerLoginConfirm,
        sharedSecret: Uint8Array,
        transcript: Uint8Array
    ): Promise<void> {
        const { serverMacKey } = deriveFinalKey(sharedSecret, transcript);
        const ok = verifyHmac(serverMacKey, transcript, serverConfirm.serverMac);
        if (!ok) throw new Error('[qh-opaque] Server MAC verification failed — possible MITM or replay.');
    }
}

// ── Envelope encryption (AES-256-GCM) ───────────────────────────────────────

const NONCE_LEN = 12;
const TAG_LEN = 16;

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    const ab = new ArrayBuffer(u8.byteLength);
    new Uint8Array(ab).set(u8);
    return ab;
}


async function encryptEnvelope(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    const { webcrypto } = await import('node:crypto');
    const cryptoKey = await webcrypto.subtle.importKey(
        'raw', toArrayBuffer(key), { name: 'AES-GCM' }, false, ['encrypt']
    );
    const nonce = webcrypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: TAG_LEN * 8 },
        cryptoKey,
        toArrayBuffer(plaintext)
    );
    const out = new Uint8Array(NONCE_LEN + ct.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(ct), NONCE_LEN);
    return out;
}

async function decryptEnvelope(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const { webcrypto } = await import('node:crypto');
    const nonce = data.subarray(0, NONCE_LEN);
    const ct = data.subarray(NONCE_LEN);
    const cryptoKey = await webcrypto.subtle.importKey(
        'raw', toArrayBuffer(key), { name: 'AES-GCM' }, false, ['decrypt']
    );
    try {
        const pt = await webcrypto.subtle.decrypt(
            { name: 'AES-GCM', iv: toArrayBuffer(nonce), tagLength: TAG_LEN * 8 },
            cryptoKey,
            toArrayBuffer(ct)
        );
        return new Uint8Array(pt);
    } catch {
        throw new Error('[qh-opaque] Envelope decryption failed — wrong password or corrupted envelope.');
    }
}