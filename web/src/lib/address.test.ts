import { describe, it, expect } from 'vitest';
import { inspectAddress } from './address';

describe('inspectAddress', () => {
  it('accepts known-good addresses', () => {
    expect(inspectAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')).toEqual({ valid: true, type: 'P2PKH' });
    expect(inspectAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).toEqual({ valid: true, type: 'P2SH' });
    expect(inspectAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toEqual({ valid: true, type: 'P2WPKH' });
  });
  it('rejects typos and junk', () => {
    expect(inspectAddress('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMX').valid).toBe(false);
    expect(inspectAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5').valid).toBe(false);
    expect(inspectAddress('').valid).toBe(false);
    expect(inspectAddress('hello').valid).toBe(false);
  });
});
