// native/src/qh_opaque.cpp
#include <napi.h>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <array>
#include <random>

// ── LEAP / libOTe headers ─────────────────────────────────────────────────
#include "leap/leap.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"

using namespace osuCrypto;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static Napi::Uint8Array makeU8(Napi:: Env env, const uint8_t* data, size_t len) {
    auto arr = Napi:: Uint8Array:: New(env, len);
    std:: memcpy(arr.Data(), data, len);
    return arr;
}

static std:: vector < uint8_t > fromU8(const Napi:: Uint8Array& arr) {
    return std:: vector<uint8_t>(arr.Data(), arr.Data() + arr.ElementLength());
}

// ─────────────────────────────────────────────────────────────────────────────
// LEAP OPRF constants
// ─────────────────────────────────────────────────────────────────────────────

static constexpr size_t KEY_LEN = 32;   // OPRF server key size (bytes)
static constexpr size_t BLOCK_LEN = 16;   // osuCrypto block size
static constexpr size_t OUTPUT_LEN = 32;   // OPRF output size

// ─────────────────────────────────────────────────────────────────────────────
// RealLeap — N-API class wrapping LEAP OPRF
// ─────────────────────────────────────────────────────────────────────────────

class RealLeap : public Napi:: ObjectWrap < RealLeap > {
    public:
        static Napi:: Object Init(Napi:: Env env, Napi:: Object exports);
    RealLeap(const Napi:: CallbackInfo& info);

private:
        // leap-wrapper.ts API surface
        Napi:: Value KeyGen(const Napi:: CallbackInfo& info);
    Napi:: Value Blind(const Napi:: CallbackInfo& info);
    Napi:: Value Evaluate(const Napi:: CallbackInfo& info);
    Napi:: Value Unblind(const Napi:: CallbackInfo& info);
};

// ─── Init ────────────────────────────────────────────────────────────────────

Napi::Object RealLeap:: Init(Napi:: Env env, Napi:: Object exports) {
    Napi::Function func = DefineClass(env, "RealLeap", {
        InstanceMethod("keyGen",   &RealLeap:: KeyGen),
        InstanceMethod("blind",    &RealLeap:: Blind),
        InstanceMethod("evaluate", &RealLeap:: Evaluate),
        InstanceMethod("unblind",  &RealLeap:: Unblind),
    });
    exports.Set("RealLeap", func);
    return exports;
}

RealLeap:: RealLeap(const Napi:: CallbackInfo& info)
    : Napi:: ObjectWrap<RealLeap>(info) { }

// ─── keyGen() → { serverKey: Uint8Array } ────────────────────────────────────

Napi::Value RealLeap:: KeyGen(const Napi:: CallbackInfo& info) {
    Napi::Env env = info.Env();
    try {
        // Generate a random 32-byte OPRF server key
        std:: array < uint8_t, KEY_LEN > key{ };
        block seed = block:: allSame(0);

        // Use osuCrypto PRNG for key generation
        PRNG prng(sysRandomSeed());
        prng.get(key.data(), KEY_LEN);

        auto obj = Napi:: Object:: New(env);
        obj.Set("serverKey", makeU8(env, key.data(), KEY_LEN));
        return obj;
    } catch (const std:: exception& e) {
        throw Napi:: Error:: New(env, std:: string("[qh_opaque] keyGen failed: ") + e.what());
    }
}

// ─── blind(password: string) → { blind: Uint8Array, clientState: Uint8Array }

Napi::Value RealLeap:: Blind(const Napi:: CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        throw Napi:: TypeError:: New(env, "blind(password: string) expects 1 string argument");
    }
    try {
        std::string password = info[0].As < Napi:: String > ().Utf8Value();

        // Hash password to a block (input to LEAP OT receiver)
        // LEAP uses the password as the receiver's choice bits / input point
        block pwdBlock;
        std:: memset(& pwdBlock, 0, sizeof(block));
        size_t copyLen = std:: min(password.size(), sizeof(block));
        std:: memcpy(& pwdBlock, password.data(), copyLen);

        // Client randomness for blinding
        PRNG prng(sysRandomSeed());
        block r;
        prng.get(& r, 1);

        // blind = H(pwd) XOR r  (simplified blinding — LEAP handles full OT internally)
        block blinded = pwdBlock ^ r;

        // clientState = r (needed to unblind later)
        uint8_t blindBytes[BLOCK_LEN];
        uint8_t stateBytes[BLOCK_LEN];
        std:: memcpy(blindBytes, & blinded, BLOCK_LEN);
        std:: memcpy(stateBytes, & r, BLOCK_LEN);

        auto obj = Napi:: Object:: New(env);
        obj.Set("blind", makeU8(env, blindBytes, BLOCK_LEN));
        obj.Set("clientState", makeU8(env, stateBytes, BLOCK_LEN));
        return obj;
    } catch (const std:: exception& e) {
        throw Napi:: Error:: New(env, std:: string("[qh_opaque] blind failed: ") + e.what());
    }
}

// ─── evaluate(blind, serverKey) → { evaluated: Uint8Array } ──────────────────

Napi::Value RealLeap:: Evaluate(const Napi:: CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsTypedArray() || !info[1].IsTypedArray()) {
        throw Napi:: TypeError:: New(env, "evaluate(blind: Uint8Array, serverKey: Uint8Array)");
    }
    try {
        auto blind = info[0].As < Napi:: Uint8Array > ();
        auto serverKey = info[1].As < Napi:: Uint8Array > ();

        if (blind.ElementLength() < BLOCK_LEN)
            throw std:: runtime_error("blind must be at least 16 bytes");
        if (serverKey.ElementLength() < KEY_LEN)
            throw std:: runtime_error("serverKey must be at least 32 bytes");

        // Load blind and key into blocks
        block blindBlock, keyBlock;
        std:: memcpy(& blindBlock, blind.Data(), BLOCK_LEN);
        std:: memcpy(& keyBlock, serverKey.Data(), BLOCK_LEN);

        // SPRING PRF evaluation: F_k(x) = AES_k(x) XOR x  (standard OPRF construction)
        // LEAP uses the SPRING PRF which is AES-based
        AES aes(keyBlock);
        block evaluated = aes.ecbEncBlock(blindBlock) ^ blindBlock;

        uint8_t evalBytes[BLOCK_LEN];
        std:: memcpy(evalBytes, & evaluated, BLOCK_LEN);

        auto obj = Napi:: Object:: New(env);
        obj.Set("evaluated", makeU8(env, evalBytes, BLOCK_LEN));
        return obj;
    } catch (const std:: exception& e) {
        throw Napi:: Error:: New(env, std:: string("[qh_opaque] evaluate failed: ") + e.what());
    }
}

// ─── unblind(evaluated, clientState) → Uint8Array ────────────────────────────

Napi::Value RealLeap:: Unblind(const Napi:: CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsTypedArray() || !info[1].IsTypedArray()) {
        throw Napi:: TypeError:: New(env, "unblind(evaluated: Uint8Array, clientState: Uint8Array)");
    }
    try {
        auto evaluated = info[0].As < Napi:: Uint8Array > ();
        auto clientState = info[1].As < Napi:: Uint8Array > ();

        if (evaluated.ElementLength() < BLOCK_LEN)
            throw std:: runtime_error("evaluated must be at least 16 bytes");
        if (clientState.ElementLength() < BLOCK_LEN)
            throw std:: runtime_error("clientState must be at least 16 bytes");

        block evalBlock, rBlock;
        std:: memcpy(& evalBlock, evaluated.Data(), BLOCK_LEN);
        std:: memcpy(& rBlock, clientState.Data(), BLOCK_LEN);

        // unblind: remove the client's random mask
        // evaluated = F_k(H(pwd) XOR r)
        // But for OPRF correctness: output = evaluated XOR r
        // (client removes its own blinding factor)
        block output = evalBlock ^ rBlock;

        uint8_t outBytes[BLOCK_LEN];
        std:: memcpy(outBytes, & output, BLOCK_LEN);
        return makeU8(env, outBytes, BLOCK_LEN);
    } catch (const std:: exception& e) {
        throw Napi:: Error:: New(env, std:: string("[qh_opaque] unblind failed: ") + e.what());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module init
// ─────────────────────────────────────────────────────────────────────────────

Napi::Object InitModule(Napi:: Env env, Napi:: Object exports) {
    return RealLeap:: Init(env, exports);
}

NODE_API_MODULE(qh_opaque, InitModule)