import { createHmac, createHash, timingSafeEqual } from 'node:crypto';

// ── HKDF ────────────────────────────────────────────────────────────────────

export function hkdf(
    input: Uint8Array,
    label: string,
    length: number,
    salt?: Uint8Array
): Uint8Array {
    const saltBuf = salt ?? Buffer.alloc(32, 0);

    // Extract
    const prk = createHmac('sha256', saltBuf).update(input).digest();

    // Expand
    const info = Buffer.from(label, 'utf8');
    const blocks = Math.ceil(length / 32);
    const okm = Buffer.alloc(blocks * 32);
    let prev = Buffer.alloc(0);

    for (let i = 0; i < blocks; i++) {
        const counter = Buffer.from([i + 1]);
        prev = createHmac('sha256', prk)
            .update(prev)
            .update(info)
            .update(counter)
            .digest();
        prev.copy(okm, i * 32);
    }

    return okm.subarray(0, length);
}

// ── HMAC ────────────────────────────────────────────────────────────────────

export function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
    return createHmac('sha256', key).update(data).digest();
}

export function verifyHmac(
    key: Uint8Array,
    data: Uint8Array,
    expected: Uint8Array
): boolean {
    const actual = Buffer.from(hmac(key, data));
    const exp = Buffer.from(expected);
    if (actual.length !== exp.length) return false;
    return timingSafeEqual(actual, exp);
}

// ── Transcript ───────────────────────────────────────────────────────────────

export function transcriptHash(messages: Uint8Array[]): Uint8Array {
    const h = createHash('sha256');
    for (const m of messages) {
        // Length-prefix each message so concatenation is unambiguous
        const len = Buffer.alloc(4);
        len.writeUInt32BE(m.length, 0);
        h.update(len);
        h.update(m);
    }
    return h.digest();
}

// ── Final key derivation ─────────────────────────────────────────────────────

export interface DerivedKeys {
    sessionKey: Uint8Array;      // 32 bytes — the shared session key
    clientMacKey: Uint8Array;    // 32 bytes — client confirmation MAC key
    serverMacKey: Uint8Array;    // 32 bytes — server confirmation MAC key
}

export function deriveFinalKey(
    prk1: Uint8Array,
    transcript: Uint8Array,
    kq?: Uint8Array              // optional QKD key, Phase 2
): DerivedKeys {
    // Mix in k_q if present
    const ikm = kq
        ? Buffer.concat([prk1, kq])
        : prk1;

    const sessionKey = hkdf(ikm, `qh-opaque-session-key:${bufHex(transcript)}`, 32);
    const clientMacKey = hkdf(ikm, `qh-opaque-client-mac:${bufHex(transcript)}`, 32);
    const serverMacKey = hkdf(ikm, `qh-opaque-server-mac:${bufHex(transcript)}`, 32);

    return { sessionKey, clientMacKey, serverMacKey };
}

// ── Internal helper ──────────────────────────────────────────────────────────

function bufHex(b: Uint8Array): string {
    return Buffer.from(b).toString('hex');
}