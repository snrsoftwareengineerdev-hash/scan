import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { base58check, bech32 } from '@scure/base';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const b58c = base58check(sha256);

export interface DerivedKey {
  keyHex: string;
  pubkeyCompressed: string;
  p2pkhCompressed: string;
  p2pkhUncompressed: string;
  p2wpkh: string;
  wifCompressed: string;
  wifUncompressed: string;
}

export const hash160 = (b: Uint8Array) => ripemd160(sha256(b));

const p2pkh = (pub: Uint8Array) => b58c.encode(Uint8Array.from([0x00, ...hash160(pub)]));

export function parseKeyHex(input: string): Uint8Array {
  const s = input.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{1,64}$/.test(s)) throw new Error('Key must be 1–64 hex characters');
  const bytes = hexToBytes(s.padStart(64, '0'));
  const n = BigInt('0x' + s);
  if (n <= 0n || n >= secp256k1.CURVE.n) throw new Error('Key must be in 1..n-1');
  return bytes;
}

export function deriveKey(keyHex: string): DerivedKey {
  const key = parseKeyHex(keyHex);
  const c = secp256k1.getPublicKey(key, true);
  const u = secp256k1.getPublicKey(key, false);
  return {
    keyHex: bytesToHex(key),
    pubkeyCompressed: bytesToHex(c),
    p2pkhCompressed: p2pkh(c),
    p2pkhUncompressed: p2pkh(u),
    p2wpkh: bech32.encode('bc', [0, ...bech32.toWords(hash160(c))]),
    wifCompressed: wifEncode(key, true),
    wifUncompressed: wifEncode(key, false),
  };
}

export function wifEncode(key: Uint8Array, compressed: boolean): string {
  return b58c.encode(Uint8Array.from([0x80, ...key, ...(compressed ? [1] : [])]));
}

export function wifDecode(wif: string): { keyHex: string; compressed: boolean } {
  const d = b58c.decode(wif.trim());
  if (d[0] !== 0x80 || (d.length !== 33 && d.length !== 34) || (d.length === 34 && d[33] !== 1)) {
    throw new Error('Not a mainnet WIF private key');
  }
  return { keyHex: bytesToHex(d.slice(1, 33)), compressed: d.length === 34 };
}

/** Classic (insecure) brainwallet: key = sha256(passphrase). For education only. */
export function brainwallet(passphrase: string): DerivedKey {
  return deriveKey(bytesToHex(sha256(new TextEncoder().encode(passphrase))));
}

/** Cryptographically secure random key (CSPRNG). */
export function randomKey(): string {
  return bytesToHex(secp256k1.utils.randomPrivateKey());
}

export function isValidP2pkh(addr: string): boolean {
  try {
    const d = b58c.decode(addr);
    return d.length === 21 && d[0] === 0;
  } catch {
    return false;
  }
}
