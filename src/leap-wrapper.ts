import { createRequire } from 'node:module';

// ── Types ────────────────────────────────────────────────────────────────────

export interface LeapKeyPair {
    serverKey: Uint8Array;   // 32 bytes — per-user OPRF key
}

export interface BlindResult {
    blind: Uint8Array;       // blinded password sent to server
    clientState: Uint8Array; // secret client state needed for unblind
}

export interface EvaluateResult {
    evaluated: Uint8Array;   // server's OPRF evaluation
}

export interface LeapOPRF {
    keyGen(): LeapKeyPair;
    blind(password: string): BlindResult;
    evaluate(blind: Uint8Array, serverKey: Uint8Array): EvaluateResult;
    unblind(evaluated: Uint8Array, clientState: Uint8Array): Uint8Array;
}

// ── Loader ───────────────────────────────────────────────────────────────────

let _instance: LeapOPRF | null = null;

export async function getLeap(): Promise<LeapOPRF> {
    if (_instance) return _instance;

    const platform = process.platform;  // linux, darwin
    const arch = process.arch;          // x64, arm64

    const addonPath = new URL(
        `../../native/${platform}-${arch}/qh_opaque.node`,
        import.meta.url
    );

    try {
        const require = createRequire(import.meta.url);
        const addon = require(addonPath.pathname) as { RealLeap: new () => LeapOPRF };
        _instance = new addon.RealLeap();
        return _instance;
    } catch (err) {
        throw new Error(
            `[qh-opaque] Failed to load native LEAP addon for ${platform}-${arch}.\n` +
            `Expected: ${addonPath.pathname}\n` +
            `Build with GitHub Actions or directly on Linux/macOS, then place the .node file there.\n` +
            `Original error: ${(err as Error).message}`
        );
    }
}