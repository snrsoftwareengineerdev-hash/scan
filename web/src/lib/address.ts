import { base58check, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

export type AddressInfo = { valid: true; type: 'P2PKH' | 'P2SH' | 'P2WPKH' | 'P2WSH' } | { valid: false; reason: string };

const b58c = base58check(sha256);

/** Validate a mainnet Bitcoin address (checksum and length). */
export function inspectAddress(addr: string): AddressInfo {
  const a = addr.trim();
  if (!a) return { valid: false, reason: 'empty' };
  if (/^bc1/i.test(a)) {
    try {
      const { prefix, words } = bech32.decode(a as `bc1${string}`);
      const prog = bech32.fromWords(words.slice(1));
      if (prefix !== 'bc' || words[0] !== 0) return { valid: false, reason: 'only v0 segwit supported' };
      if (prog.length === 20) return { valid: true, type: 'P2WPKH' };
      if (prog.length === 32) return { valid: true, type: 'P2WSH' };
      return { valid: false, reason: 'bad witness program length' };
    } catch {
      return { valid: false, reason: 'bad bech32 checksum' };
    }
  }
  try {
    const d = b58c.decode(a);
    if (d.length !== 21) return { valid: false, reason: 'bad length' };
    if (d[0] === 0) return { valid: true, type: 'P2PKH' };
    if (d[0] === 5) return { valid: true, type: 'P2SH' };
    return { valid: false, reason: 'unknown version byte' };
  } catch {
    return { valid: false, reason: 'bad base58 checksum' };
  }
}
