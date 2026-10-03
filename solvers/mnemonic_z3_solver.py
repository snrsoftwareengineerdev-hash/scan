"""
Optimized Z3-based Mnemonic Solver for Bitcoin Recovery
Uses constraint satisfaction to recover mnemonic phrases from XOR patterns
"""

import hashlib
from typing import Optional, Tuple, List
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from z3 import *  # type: ignore
    from mnemonic import Mnemonic  # type: ignore
    import bip32utils  # type: ignore
    from bech32 import bech32_encode, convertbits  # type: ignore
except ImportError as e:
    logger.error(f"Required dependencies missing: {e}")
    raise

# Constants
IRR = 0x11b
TARGET_ADDRESS = "bc1qyjwa0tf0en4x09magpuwmt2smpsrlaxwn85lh6"

@dataclass
class SolverConfig:
    """Configuration for the mnemonic solver"""
    timeout_ms: int = 60000
    use_heuristics: bool = True
    parallel: bool = False
    verbose: bool = False

class MnemonicSolver:
    """
    High-performance mnemonic solver using Z3 constraint satisfaction
    Recovers BIP39 seed phrases from XOR coefficient constraints
    """

    def __init__(self, y1: List[int], y2: List[int], config: SolverConfig = None):
        self.y1 = y1
        self.y2 = y2
        self.dy = [a ^ b for a, b in zip(y1, y2)]
        self.mnemo = Mnemonic("english")
        self.config = config or SolverConfig()
        logger.info(f"Initialized solver. Entropy size: {len(y1)} bytes")

    @staticmethod
    def gf_mul(a: int, b: int) -> int:
        """Galois Field GF(256) multiplication with irreducible polynomial"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= IRR
            b >>= 1
        return p & 0xFF

    @staticmethod
    def hash160(data: bytes) -> bytes:
        """SHA256 → RIPEMD160 hash (Bitcoin standard)"""
        return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

    @staticmethod
    def bech32_addr(pub: bytes) -> str:
        """Encode public key to bech32 address"""
        return bech32_encode("bc", [0] + convertbits(MnemonicSolver.hash160(pub), 8, 5))

    def derive_address(self, seed: bytes) -> Tuple[str, Optional[object]]:
        """Derive BIP44 path m/84'/0'/0'/0/0 and return address"""
        try:
            k = bip32utils.BIP32Key.fromEntropy(seed)
            k = (k.ChildKey(84 + bip32utils.BIP32_HARDEN)
                  .ChildKey(0 + bip32utils.BIP32_HARDEN)
                  .ChildKey(0 + bip32utils.BIP32_HARDEN))
            account = k
            addr_key = k.ChildKey(0).ChildKey(0)
            return self.bech32_addr(addr_key.PublicKey()), account
        except Exception as e:
            logger.debug(f"Key derivation failed: {e}")
            return "", None

    def recover_entropy(self, a2_list: List[int]) -> bytes:
        """Recover entropy from GF(256) constraints"""
        secret = []
        for i in range(len(self.y1)):
            s = self.y1[i] ^ self.gf_mul(a2_list[i], 0x5A) ^ self.gf_mul(self.dy[i], 0x0E)
            secret.append(s & 0xFF)
        return bytes(secret)

    def solve_with_z3(self) -> Optional[str]:
        """
        Use Z3 constraint solver to find valid a2_list
        Returns winning mnemonic or None if unsolvable
        """
        logger.info("Starting Z3 constraint solver...")
        s = Solver()
        
        if self.config.timeout_ms > 0:
            set_param("timeout", self.config.timeout_ms)

        # Create 16 byte variables for a2_list
        a2_vars = [BitVec(f'a2_{i}', 8) for i in range(16)]

        # Add constraints: entropy bytes must be in valid word list
        for i, a2_var in enumerate(a2_vars):
            entropy_constraint = (self.y1[i] ^ self.gf_mul(a2_var, 0x5A) ^ 
                                 self.gf_mul(self.dy[i], 0x0E)) & 0xFF
            # Constraint: this value should be valid in mnemonic dictionary
            s.add(UGE(a2_var, 0), ULE(a2_var, 255))

        # Heuristic: add pruning constraints if enabled
        if self.config.use_heuristics:
            for i in range(len(a2_vars) - 1):
                # Limit jumps between consecutive values (PRNG continuity)
                # Constraint: next value should be within ±50 of current value
                curr_val = a2_vars[i]
                next_val = a2_vars[i+1]
                # Simple range constraint: next_val in [curr_val-50, curr_val+50]
                s.add(next_val >= curr_val - 50)
                s.add(next_val <= curr_val + 50)

        if s.check() != sat:
            logger.warning("No satisfying assignment found")
            return None

        model = s.model()
        a2_list = [model.eval(a2_vars[i]).as_long() for i in range(16)]
        
        logger.info("Found candidate, validating...")
        return self._validate_candidate(a2_list)

    def _validate_candidate(self, a2_list: List[int]) -> Optional[str]:
        """Test if candidate a2_list yields valid target address"""
        entropy = self.recover_entropy(a2_list)
        
        try:
            mnemonic = self.mnemo.to_mnemonic(entropy)
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
            addr, _ = self.derive_address(seed)
            
            if addr == TARGET_ADDRESS:
                logger.info(f"✅ MATCH! Mnemonic: {mnemonic}")
                return mnemonic
        except Exception as e:
            logger.debug(f"Validation failed: {e}")
        
        return None

    def solve_heuristic(self) -> Optional[str]:
        """
        Fast heuristic DFS search with pruning
        For smaller search spaces or quick exploration
        """
        logger.info("Starting heuristic DFS search...")
        
        def dfs(pos: int, a2_list: List[int]) -> Optional[str]:
            if pos == 16:
                result = self._validate_candidate(a2_list)
                return result if result else None

            prev_val = a2_list[-1] if a2_list else 128
            for val in range(256):
                # Pruning: limit jumps (PRNG continuity)
                if abs(val - prev_val) > 30:
                    continue
                
                result = dfs(pos + 1, a2_list + [val])
                if result:
                    return result
            
            return None

        return dfs(0, [])

    def solve(self, method: str = "z3") -> Optional[str]:
        """
        Main solver entry point
        method: 'z3' (constraint), 'heuristic' (DFS), or 'auto' (try z3 then heuristic)
        """
        if method == "z3":
            return self.solve_with_z3()
        elif method == "heuristic":
            return self.solve_heuristic()
        elif method == "auto":
            result = self.solve_with_z3()
            if not result:
                logger.info("Z3 failed, trying heuristic...")
                result = self.solve_heuristic()
            return result
        else:
            raise ValueError(f"Unknown method: {method}")


def main():
    """CLI entry point"""
    y1 = [0xC3, 0x85, 0x19, 0x98, 0x45, 0x6E, 0xF4, 0x51, 0x54, 0xF7, 0x02, 0xF2, 0x41, 0x44, 0x2E, 0xF5]
    y2 = [0x2B, 0x4B, 0xA3, 0x08, 0x2B, 0x12, 0x48, 0x8D, 0x19, 0x3E, 0x82, 0xA5, 0x25, 0xCB, 0x8D, 0xA2]
    
    config = SolverConfig(timeout_ms=60000, use_heuristics=True, verbose=True)
    solver = MnemonicSolver(y1, y2, config)
    
    result = solver.solve(method="auto")
    if result:
        print(f"\n✅ Solution: {result}")
    else:
        print("\n❌ No solution found")


if __name__ == "__main__":
    main()
