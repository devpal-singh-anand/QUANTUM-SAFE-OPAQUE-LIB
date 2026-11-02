import { getLeap } from './leap-wrapper.js';
import { keyGen, decapsulate } from './mlkem.js';
import { hmac, verifyHmac, transcriptHash, deriveFinalKey } from './keyschedule.js';
import { hkdf } from './keyschedule.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface UserRecord {
    username: string;
    oprfKey: Uint8Array;         // per-user LEAP server key
    envelope: Uint8Array;        // encrypted credential envelope
    mlkemPublicKey: Uint8Array;  // client's ML-KEM public key
}

export interface ServerRegisterRequest {
    username: string;
    blind: Uint8Array;
}

export interface ServerRegisterFinish {
    username: string;
    envelope: Uint8Array;
    mlkemPublicKey: Uint8Array;
}

export interface ServerLoginRequest {
    username: string;
    blind: Uint8Array;
}

export interface ServerLoginResponse {
    evaluated: Uint8Array;
    envelope: Uint8Array;
    mlkemPublicKey: Uint8Array;  // server's ML-KEM public key
}

export interface ClientLoginFinish {
    username: string;
    mlkemCiphertext: Uint8Array;
    clientMac: Uint8Array;
}

export interface ServerLoginConfirm {
    serverMac: Uint8Array;
}

// ── Server ───────────────────────────────────────────────────────────────────

export class QHOpaqueServer {
    // In-memory store. Replace with a real DB in production.
    private users = new Map<string, UserRecord>();

    // Server's own ML-KEM key pair (one per server, not per user)
    private serverPublicKey!: Uint8Array;
    private serverSecretKey!: Uint8Array;

    async init(): Promise<void> {
        const { publicKey, secretKey } = await keyGen();
        this.serverPublicKey = publicKey;
        this.serverSecretKey = secretKey;
    }

    // ── Registration ──────────────────────────────────────────────────────────

    async startRegister(req: ServerRegisterRequest): Promise<{ evaluated: Uint8Array }> {
        const leap = await getLeap();
        const { serverKey } = leap.keyGen();

        const { evaluated } = leap.evaluate(req.blind, serverKey);

        // Temporarily store the OPRF key keyed by username until finishRegister
        this.users.set(req.username, {
            username: req.username,
            oprfKey: serverKey,
            envelope: new Uint8Array(0),       // filled in finishRegister
            mlkemPublicKey: new Uint8Array(0), // filled in finishRegister
        });

        return { evaluated };
    }

    async finishRegister(finish: ServerRegisterFinish): Promise<void> {
        const record = this.users.get(finish.username);
        if (!record) throw new Error(`[qh-opaque] No pending registration for ${finish.username}`);

        record.envelope = finish.envelope;
        record.mlkemPublicKey = finish.mlkemPublicKey;
        this.users.set(finish.username, record);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    async startLogin(req: ServerLoginRequest): Promise<ServerLoginResponse> {
        const leap = await getLeap();

        const record = this.users.get(req.username);

        if (!record) {
            // Unknown username — return a fake plausible response to prevent
            // user enumeration. Values are deterministic on the username so
            // the same fake is returned every time for the same username.
            return this.fakeLoginResponse(req.username, req.blind);
        }

        const { evaluated } = leap.evaluate(req.blind, record.oprfKey);

        return {
            evaluated,
            envelope: record.envelope,
            mlkemPublicKey: this.serverPublicKey,
        };
    }

    async finishLogin(finish: ClientLoginFinish): Promise<ServerLoginConfirm> {
        const record = this.users.get(finish.username);
        if (!record) throw new Error('[qh-opaque] Login failed.');

        // Decapsulate to recover the shared secret
        const sharedSecret = await decapsulate(finish.mlkemCiphertext, this.serverSecretKey);

        // Recompute transcript
        const leap = await getLeap();
        // We need the evaluated value — re-evaluate with a dummy blind to get it.
        // In a real flow the server would carry this from startLogin in session state.
        // For now keep it simple: store evaluated in a pending login map.
        const pending = this.pendingLogins.get(finish.username);
        if (!pending) throw new Error('[qh-opaque] No pending login for this username.');

        const transcript = transcriptHash([
            pending.evaluated,
            finish.mlkemCiphertext,
        ]);

        const { clientMacKey, serverMacKey } = deriveFinalKey(sharedSecret, transcript);

        // Verify client MAC — fail closed
        const ok = verifyHmac(clientMacKey, transcript, finish.clientMac);
        if (!ok) throw new Error('[qh-opaque] Client MAC verification failed.');

        // Clear pending login
        this.pendingLogins.delete(finish.username);

        // Send server MAC
        const serverMac = hmac(serverMacKey, transcript);
        return { serverMac };
    }

    // ── Pending login state ───────────────────────────────────────────────────

    private pendingLogins = new Map<string, { evaluated: Uint8Array }>();

    async startLoginWithState(req: ServerLoginRequest): Promise<ServerLoginResponse> {
        const response = await this.startLogin(req);
        this.pendingLogins.set(req.username, { evaluated: response.evaluated });
        return response;
    }

    // ── Fake response for unknown usernames ───────────────────────────────────

    private fakeLoginResponse(username: string, blind: Uint8Array): ServerLoginResponse {
        // Deterministic fake keyed on username so repeated probes get the same answer
        const fakeKey = hkdf(Buffer.from(username), 'qh-opaque-fake-oprf-key', 32);
        const fakeEval = hmac(fakeKey, blind);
        const fakeEnv = hkdf(Buffer.from(username), 'qh-opaque-fake-envelope', 64);
        const fakePub = hkdf(Buffer.from(username), 'qh-opaque-fake-mlkem-pub', 32);
        return {
            evaluated: fakeEval,
            envelope: fakeEnv,
            mlkemPublicKey: fakePub,
        };
    }
}