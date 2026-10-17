import { base64url, cryptoBytes, fromBase64url, equalBytes } from "./encoding.js";

const PKCS8_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

function keyPair(crypto: Crypto): SubtleCrypto { return crypto.subtle; }
function pkcs8(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new HyperKeyKeyError("Ed25519 seed must be 32 bytes");
  const result = new Uint8Array(PKCS8_PREFIX.length + seed.length);
  result.set(PKCS8_PREFIX); result.set(seed, PKCS8_PREFIX.length);
  return result;
}

function jwkPart(value: JsonWebKey, name: "d" | "x"): Uint8Array {
  const encoded = value[name];
  if (typeof encoded !== "string") throw new HyperKeyKeyError("Ed25519 JWK lacks canonical key material");
  return fromBase64url(encoded, 32);
}

/** Generate the one conventional signing key; this API never creates MLS credentials. */
export async function generateEd25519SeedPair(crypto: Crypto = globalThis.crypto): Promise<Readonly<{ seed: Uint8Array; publicKey: Uint8Array }>> {
  const pair = await keyPair(crypto).generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!isKeyPair(pair)) throw new HyperKeyKeyError("Ed25519 key generation did not return a pair");
  const privateJwk = await keyPair(crypto).exportKey("jwk", pair.privateKey);
  const publicJwk = await keyPair(crypto).exportKey("jwk", pair.publicKey);
  const seed = jwkPart(privateJwk, "d"), publicKey = jwkPart(publicJwk, "x");
  if (!equalBytes(await publicKeyForEd25519Seed(seed, crypto), publicKey)) throw new HyperKeyKeyError("Ed25519 implementation returned inconsistent key pair");
  return Object.freeze({ seed, publicKey });
}

/** Derives the canonical raw Ed25519 public key from the canonical 32-byte seed. */
export async function publicKeyForEd25519Seed(seed: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<Uint8Array> {
  const privateKey = await keyPair(crypto).importKey("pkcs8", cryptoBytes(pkcs8(seed)), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await keyPair(crypto).exportKey("jwk", privateKey);
  return jwkPart(jwk, "x");
}

/** Conventional signing only. The seed is never used as MLS input. */
export async function signEd25519(seed: Uint8Array, message: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<Uint8Array> {
  if (!(message instanceof Uint8Array)) throw new HyperKeyKeyError("Signing input must be bytes");
  const encoded = pkcs8(seed);
  try {
    const privateKey = await crypto.subtle.importKey("pkcs8", cryptoBytes(encoded), { name: "Ed25519" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, cryptoBytes(message)));
  } finally { encoded.fill(0); }
}

export async function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<boolean> {
  assertEd25519PublicKey(publicKey);
  if (!(message instanceof Uint8Array) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
  const key = await crypto.subtle.importKey("raw", cryptoBytes(publicKey), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, cryptoBytes(signature), cryptoBytes(message));
}

export const encodeEd25519PublicKey = (key: Uint8Array): string => base64url(assertEd25519PublicKey(key));
export function decodeEd25519PublicKey(value: string): Uint8Array { return fromBase64url(value, 32); }
export function assertEd25519PublicKey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new HyperKeyKeyError("Ed25519 public key must be 32 bytes");
  return new Uint8Array(value);
}

export class HyperKeyKeyError extends Error { override name = "HyperKeyKeyError"; }

function isKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return typeof value === "object" && value !== null && "privateKey" in value && "publicKey" in value;
}
