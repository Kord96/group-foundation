import { GroupError } from "./contracts.js";

export type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };

export function canonicalJson(value: Json): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) fail("invalid-wire", "numbers must be safe integers"); return String(value); }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) fail("invalid-wire", "object prototype is not canonical");
  const record = value as { readonly [key: string]: Json };
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key]!)}`).join(",")}}`;
}
export function bytesToBase64url(value: Uint8Array): string {
  let binary = ""; for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
export function base64urlToBytes(value: string, limit: number, field: string): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9_-]{2,}|[A-Za-z0-9_-])$/u.test(value) || value.length > Math.ceil(limit * 4 / 3)) fail("invalid-wire", `${field} is not canonical base64url`);
  let binary: string;
  try { binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4)); } catch { fail("invalid-wire", `${field} is not base64url`); }
  const bytes = Uint8Array.from(binary!, char => char.charCodeAt(0));
  if (!bytes.length || bytes.length > limit || bytesToBase64url(bytes) !== value) fail("invalid-wire", `${field} is outside bounds or noncanonical`);
  return bytes;
}
function fail(code: string, message: string): never { throw new GroupError(code, message); }
