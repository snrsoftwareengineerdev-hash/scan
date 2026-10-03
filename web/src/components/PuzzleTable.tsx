import { useDeferredValue, useMemo, useState } from 'react';
import { PUZZLES, verifyPuzzle } from '../lib/puzzles';

type Filter = 'all' | 'solved' | 'unsolved';

export function PuzzleTable() {
  const [filter, setFilter] = useState<Filter>('all');
  const [q, setQ] = useState('');
  const dq = useDeferredValue(q.trim().toLowerCase());
  const rows = useMemo(
    () =>
      PUZZLES.filter((p) => (filter === 'all' || (filter === 'solved') === p.solved) && (!dq || String(p.id) === dq || p.address.toLowerCase().includes(dq))),
    [filter, dq],
  );
  const verified = useMemo(() => new Map(PUZZLES.filter((p) => p.privateKey).map((p) => [p.id, verifyPuzzle(p)])), []);
  return (
    <section className="card">
      <h2>Puzzle catalogue</h2>
      <p className="dim">{PUZZLES.filter((p) => p.solved).length} solved · {PUZZLES.filter((p) => !p.solved).length} unsolved. Solved keys are re-verified against their address in your browser.</p>
      <div className="row">
        {(['all', 'solved', 'unsolved'] as Filter[]).map((f) => (
          <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>{f}</button>
        ))}
        <input style={{ flex: 1, minWidth: 180 }} aria-label="Search" placeholder="puzzle # or address" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <table>
        <thead><tr><th>#</th><th>Address</th><th>Status</th><th>Key</th></tr></thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.id}>
              <td>{p.id}</td>
              <td className="mono">{p.address}</td>
              <td>{p.solved ? 'solved' : 'unsolved'}</td>
              <td className="mono">
                {p.privateKey ? <>{p.privateKey} <span className={verified.get(p.id) ? 'ok' : 'bad'}>{verified.get(p.id) ? '✓' : '✗'}</span></> : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
