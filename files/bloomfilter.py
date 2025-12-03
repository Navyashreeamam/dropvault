import mmh3
from bitarray import bitarray
import math

try:
    from bitarray import bitarray
    BITARRAY_AVAILABLE = True
except ImportError:
    BITARRAY_AVAILABLE = False
    print("Warning: bitarray not available, using fallback implementation")


class BloomFilter:
    def __init__(self, m=1_000_000, k=5):
        self.m = m
        self.k = k
        self.bit_array = bitarray(m)
        self.bit_array.setall(0)

    def _hashes(self, item):
        return [mmh3.hash(item, seed) % self.m for seed in range(self.k)]

    def add(self, item):
        for h in self._hashes(item):
            self.bit_array[h] = 1

    def contains(self, item):
        return all(self.bit_array[h] for h in self._hashes(item))