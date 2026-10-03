import { describe, it, expect } from 'vitest';
import { deriveKey, wifDecode, brainwallet, parseKeyHex, isValidP2pkh, randomKey } from './keys';
import { PUZZLES, verifyPuzzle } from './puzzles';

describe('keys', () => {
  it('derives the well-known key=1 addresses', () => {
    const d = deriveKey('1');
    expect(d.p2pkhCompressed).toBe('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
    expect(d.p2pkhUncompressed).toBe('1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm');
    expect(d.wifCompressed).toBe('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
    expect(d.p2wpkh).toBe('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  });
  it('round-trips WIF', () => {
    const d = deriveKey('abc123');
    expect(wifDecode(d.wifCompressed)).toEqual({ keyHex: d.keyHex, compressed: true });
    expect(wifDecode(d.wifUncompressed).compressed).toBe(false);
  });
  it('rejects bad keys', () => {
    expect(() => parseKeyHex('0')).toThrow();
    expect(() => parseKeyHex('zz')).toThrow();
    expect(() => parseKeyHex('f'.repeat(64))).toThrow();
    expect(() => wifDecode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')).toThrow();
  });
  it('brainwallet of empty string is the known weak key', () => {
    expect(brainwallet('').keyHex).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
  it('random keys are valid and unique', () => {
    const a = randomKey(), b = randomKey();
    expect(a).not.toBe(b);
    expect(() => parseKeyHex(a)).not.toThrow();
  });
});

describe('puzzle dataset', () => {
  it('has 160 puzzles with valid addresses and consecutive ids', () => {
    expect(PUZZLES).toHaveLength(160);
    PUZZLES.forEach((p, i) => {
      expect(p.id).toBe(i + 1);
      expect(isValidP2pkh(p.address)).toBe(true);
    });
  });
  it('every published solution maps to its address and lies in its range', () => {
    const solved = PUZZLES.filter((p) => p.privateKey);
    expect(solved.length).toBeGreaterThan(50);
    for (const p of solved) {
      expect(verifyPuzzle(p), `puzzle ${p.id}`).toBe(true);
      const k = BigInt('0x' + p.privateKey), lo = BigInt('0x' + p.start), hi = BigInt('0x' + p.end);
      expect(k >= lo && k <= hi, `puzzle ${p.id} range`).toBe(true);
    }
  });
});
