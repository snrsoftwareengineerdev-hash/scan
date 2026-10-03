import { useState } from 'react';
import { inspectAddress } from '../lib/address';

export function AddressCheck() {
  const [a, setA] = useState('');
  const r = a.trim() ? inspectAddress(a) : null;
  return (
    <section className="card">
      <h2>Address validator</h2>
      <p className="dim">Checks the checksum and type of a mainnet address, offline.</p>
      <div className="row">
        <input aria-label="Address" value={a} onChange={(e) => setA(e.target.value)} placeholder="1… / 3… / bc1…" spellCheck={false} />
        <button onClick={() => navigator.clipboard?.readText().then(setA).catch(() => {})}>Paste</button>
      </div>
      {r && (r.valid ? <p className="ok">Valid {r.type} address</p> : <p className="bad">Invalid: {r.reason}</p>)}
    </section>
  );
}
