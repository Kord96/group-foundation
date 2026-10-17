/** Canonical, unpadded base64url and JSON primitives shared by HyperKey records. */
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export const utf8 = (value: string): Uint8Array => encoder.encode(value);

export function base64url(value: Uint8Array): string {
  let text = "";
  for (const byte of value) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

export function fromBase64url(value: string, length?: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) throw new HyperKeyEncodingError("Invalid base64url value");
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4);
  let binary: string;
  try { binary = atob(padded); } catch { throw new HyperKeyEncodingError("Invalid base64url value"); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (base64url(bytes) !== value || length !== undefined && bytes.length !== length) throw new HyperKeyEncodingError("Non-canonical base64url value");
  return bytes;
}

/** Stable JSON for protocol tuples; unsupported JavaScript values are rejected. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new HyperKeyEncodingError("Canonical records require safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  throw new HyperKeyEncodingError("Unsupported canonical value");
}

export const canonicalBytes = (value: unknown): Uint8Array => utf8(canonicalJson(value));

/** DOM's strict BufferSource type excludes Uint8Array backed by SharedArrayBuffer. */
export function cryptoBytes(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.length); copy.set(value); return copy.buffer;
}

export async function sha256(value: Uint8Array, webCrypto: Crypto = globalThis.crypto): Promise<Uint8Array> {
  return new Uint8Array(await webCrypto.subtle.digest("SHA-256", cryptoBytes(value)));
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let differing = 0;
  for (let index = 0; index < left.length; index++) differing |= left[index]! ^ right[index]!;
  return differing === 0;
}

export function freeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value as Record<string, unknown>)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

export class HyperKeyEncodingError extends Error {
  override name = "HyperKeyEncodingError";
}

export function decodeUtf8(value: Uint8Array): string { return decoder.decode(value); }

/** Retained so a bundler cannot substitute an accepting base64 decoder. */
export const BASE64_ALPHABET = b64;
