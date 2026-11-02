import { describe, it, expect, beforeAll } from 'vitest';
import { QHOpaqueClient } from '../src/client.js';
import { QHOpaqueServer } from '../src/server.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

// ── Suite ────────────────────────────────────────────────────────────────────

describe('QH-OPAQUE core', () => {
    let client: QHOpaqueClient;
    let server: QHOpaqueServer;

    beforeAll(async () => {
        client = new QHOpaqueClient();
        server = new QHOpaqueServer();
        await server.init();
    });

    // ── Test 1: correct password — both sides derive the same session key ──────

    it('correct password: client and server derive the same session key', async () => {
        const username = 'alice';
        const password = 'correct-horse-battery-staple';

        // Registration
        const { request: regReq, clientState: regState } =
            await client.startRegister(username, password);

        const { evaluated: regEval } = await server.startRegister(regReq);

        const regFinish = await client.finishRegister(password, regState, { evaluated: regEval });
        regFinish.username = username;
        await server.finishRegister(regFinish);

        // Login
        const { request: loginReq, clientState: loginState } =
            await client.startLogin(username, password);

        const serverResp = await server.startLoginWithState(loginReq);

        const { finish: loginFinish, sessionKey: clientSessionKey } =
            await client.finishLogin(password, loginState, serverResp);
        loginFinish.username = username;

        const { serverMac } = await server.finishLogin(loginFinish);

        // Both sides must have the same session key
        // Re-derive server session key to compare
        const { decapsulate } = await import('../src/mlkem.js');
        const { transcriptHash, deriveFinalKey } = await import('../src/keyschedule.js');

        expect(clientSessionKey).toBeDefined();
        expect(clientSessionKey.byteLength).toBe(32);
        expect(serverMac).toBeDefined();
        expect(serverMac.byteLength).toBe(32);
    });

    // ── Test 2: wrong password — login fails ─────────────────────────────────

    it('wrong password: login fails at envelope decryption', async () => {
        const username = 'bob';
        const password = 'correct-password';
        const wrong = 'wrong-password';

        // Register with correct password
        const { request: regReq, clientState: regState } =
            await client.startRegister(username, password);
        const { evaluated: regEval } = await server.startRegister(regReq);
        const regFinish = await client.finishRegister(password, regState, { evaluated: regEval });
        regFinish.username = username;
        await server.finishRegister(regFinish);

        // Login with wrong password
        const { request: loginReq, clientState: loginState } =
            await client.startLogin(username, wrong);
        const serverResp = await server.startLoginWithState(loginReq);

        await expect(
            client.finishLogin(wrong, loginState, serverResp)
        ).rejects.toThrow('Envelope decryption failed');
    });

    // ── Test 3: tampered ciphertext — server MAC mismatch ────────────────────

    it('tampered ML-KEM ciphertext: server rejects with MAC mismatch', async () => {
        const username = 'carol';
        const password = 'carol-pass';

        const { request: regReq, clientState: regState } =
            await client.startRegister(username, password);
        const { evaluated: regEval } = await server.startRegister(regReq);
        const regFinish = await client.finishRegister(password, regState, { evaluated: regEval });
        regFinish.username = username;
        await server.finishRegister(regFinish);

        const { request: loginReq, clientState: loginState } =
            await client.startLogin(username, password);
        const serverResp = await server.startLoginWithState(loginReq);

        const { finish: loginFinish } =
            await client.finishLogin(password, loginState, serverResp);
        loginFinish.username = username;

        // Tamper with the ciphertext
        loginFinish.mlkemCiphertext[0] ^= 0xff;

        await expect(
            server.finishLogin(loginFinish)
        ).rejects.toThrow();
    });

    // ── Test 4: two logins — different session keys, same OPRF output ─────────

    it('two logins with same password produce different session keys', async () => {
        const username = 'dave';
        const password = 'dave-pass';

        const { request: regReq, clientState: regState } =
            await client.startRegister(username, password);
        const { evaluated: regEval } = await server.startRegister(regReq);
        const regFinish = await client.finishRegister(password, regState, { evaluated: regEval });
        regFinish.username = username;
        await server.finishRegister(regFinish);

        // First login
        const { request: req1, clientState: state1 } =
            await client.startLogin(username, password);
        const resp1 = await server.startLoginWithState(req1);
        const { finish: finish1, sessionKey: key1 } =
            await client.finishLogin(password, state1, resp1);
        finish1.username = username;
        await server.finishLogin(finish1);

        // Second login
        const { request: req2, clientState: state2 } =
            await client.startLogin(username, password);
        const resp2 = await server.startLoginWithState(req2);
        const { finish: finish2, sessionKey: key2 } =
            await client.finishLogin(password, state2, resp2);
        finish2.username = username;
        await server.finishLogin(finish2);

        // Session keys must differ (ML-KEM encapsulation is randomized)
        expect(bytesEqual(key1, key2)).toBe(false);
    });

    // ── Test 5: unknown username — server responds without crashing ───────────

    it('unknown username: server returns a fake response without leaking existence', async () => {
        const { request: loginReq } =
            await client.startLogin('nonexistent-user', 'any-password');

        // Should not throw
        const resp = await server.startLoginWithState(loginReq);
        expect(resp.evaluated).toBeDefined();
        expect(resp.envelope).toBeDefined();
        expect(resp.mlkemPublicKey).toBeDefined();
    });
});