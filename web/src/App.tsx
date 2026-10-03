import { useState } from 'react';
import { KeyTools } from './components/KeyTools';
import { PuzzleTable } from './components/PuzzleTable';
import { Brainwallet } from './components/Brainwallet';
import { AddressCheck } from './components/AddressCheck';

const TABS = { puzzles: PuzzleTable, keys: KeyTools, brain: Brainwallet, addr: AddressCheck } as const;
const LABELS: Record<keyof typeof TABS, string> = { puzzles: 'Puzzles', keys: 'Key tools', brain: 'Brainwallet check', addr: 'Address validator' };

export function App() {
  const [tab, setTab] = useState<keyof typeof TABS>('puzzles');
  const Tab = TABS[tab];
  return (
    <main>
      <h1>Scan — Bitcoin Puzzle Workbench</h1>
      <nav>
        {(Object.keys(TABS) as (keyof typeof TABS)[]).map((t) => (
          <button key={t} aria-pressed={tab === t} onClick={() => setTab(t)}>{LABELS[t]}</button>
        ))}
      </nav>
      <Tab />
    </main>
  );
}
