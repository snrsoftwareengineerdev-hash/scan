import raw from '../../../data/puzzles.json';
import { deriveKey } from './keys';

export interface Puzzle {
  id: number;
  address: string;
  start: string;
  end: string;
  solved: boolean;
  privateKey?: string;
  reward?: number;
}

export const PUZZLES = raw as Puzzle[];

/** Search-space size in bits for the puzzle's range. */
export const rangeBits = (p: Puzzle) => p.id;

/** Check a solved puzzle's published key really maps to its address. */
export function verifyPuzzle(p: Puzzle): boolean {
  if (!p.privateKey) return false;
  try {
    const d = deriveKey(p.privateKey);
    return d.p2pkhCompressed === p.address || d.p2pkhUncompressed === p.address;
  } catch {
    return false;
  }
}
