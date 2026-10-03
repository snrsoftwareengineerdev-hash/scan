import { useState } from 'react';
import { brainwallet } from '../lib/keys';

export function Brainwallet() {
  const [p, setP] = useState('');
  const d = p ? brainwallet(p) : null;
  return (
    <section className="card">
      <h2>Brainwallet check</h2>
      <p className="dim">
        A brainwallet uses <code>sha256(passphrase)</code> as the private key. Attackers precompute these for every common phrase, so
        funds sent to one are usually swept within seconds. Use this only to demonstrate the weakness, never to store funds.
      </p>
      <input aria-label="Passphrase" value={p} onChange={(e) => setP(e.target.value)} placeholder="passphrase" autoComplete="off" />
      {d && (
        <dl className="mono">
          <dt>Key</dt><dd>{d.keyHex}</dd>
          <dt>Address</dt><dd>{d.p2pkhCompressed}</dd>
        </dl>
      )}
    </section>
  );
}
