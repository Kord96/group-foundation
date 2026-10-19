import type { Sha256Port } from './contracts.js';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** No platform-specific encoders; the port receives a fresh UTF-8 byte array. */
export async function digest(value: string, port: Sha256Port): Promise<string> {
  const bytes = await port.sha256(new TextEncoder().encode(value));
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('sha256-output-invalid');
  let output = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index]!, second = bytes[index + 1], third = bytes[index + 2];
    output += alphabet[first >> 2]! + alphabet[((first & 3) << 4) | ((second ?? 0) >> 4)]!;
    if (second !== undefined) output += alphabet[((second & 15) << 2) | ((third ?? 0) >> 6)]!;
    if (third !== undefined) output += alphabet[third & 63]!;
  }
  return output;
}
