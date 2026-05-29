import { sha256Hex } from "./crypto.ts";

export function sha256HexBytes(input: Buffer): string {
  return sha256Hex(input);
}

export function sha256HexUtf8(input: string): string {
  return sha256Hex(input);
}
