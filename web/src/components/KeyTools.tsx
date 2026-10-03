import { useMemo, useState } from 'react';
import { deriveKey, randomKey, wifDecode } from '../lib/keys';

function analyse(input: string) {
  const s = input.trim();
  if (!s) return null;
  try {
    const hex = /^(0x)?[0-9a-fA-F]{1,64}$/.test(s) ? s : wifDecode(s).keyHex;
    return { d: deriveKey(hex) };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export function KeyTools() {
  const [input, setInput] = useState('');
  const r = useMemo(() => analyse(input), [input]);
  return (
    <section className="card">
      <h2>Key tools</h2>
      <p className="dim">Paste a hex key or WIF. Everything runs locally in your browser.</p>
      <div className="row">
        <input aria-label="Private key hex or WIF" value={input} onChange={(e) => setInput(e.target.value)} placeholder="hex or WIF" spellCheck={false} autoComplete="off" />
        <button onClick={() => setInput(randomKey())}>Random (CSPRNG)</button>
      </div>
      {r && 'error' in r && <p className="bad">{r.error}</p>}
      {r && 'd' in r && r.d && (
        <dl className="mono">
          <dt>Key</dt><dd>{r.d.keyHex}</dd>
          <dt>Public key</dt><dd>{r.d.pubkeyCompressed}</dd>
          <dt>P2PKH (c)</dt><dd>{r.d.p2pkhCompressed}</dd>
          <dt>P2PKH (u)</dt><dd>{r.d.p2pkhUncompressed}</dd>
          <dt>P2WPKH</dt><dd>{r.d.p2wpkh}</dd>
          <dt>WIF (c)</dt><dd>{r.d.wifCompressed}</dd>
          <dt>WIF (u)</dt><dd>{r.d.wifUncompressed}</dd>
        </dl>
      )}
    </section>
  );
}
