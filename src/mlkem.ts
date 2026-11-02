import { createMLKEM768 } from '@oqs/liboqs-js';

export interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

export interface Encapsulated {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}

export async function keyGen(): Promise<KeyPair> {
    const kem = await createMLKEM768();
    try {
        const { publicKey, secretKey } = kem.generateKeyPair();
        return { publicKey, secretKey };
    } finally {
        kem.destroy();
    }
}

export async function encapsulate(publicKey: Uint8Array): Promise<Encapsulated> {
    const kem = await createMLKEM768();
    try {
        const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
        return { ciphertext, sharedSecret };
    } finally {
        kem.destroy();
    }
}

export async function decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array
): Promise<Uint8Array> {
    const kem = await createMLKEM768();
    try {
        return kem.decapsulate(ciphertext, secretKey);
    } finally {
        kem.destroy();
    }
}