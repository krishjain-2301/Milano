from __future__ import annotations


class ReplayWindow:
    def __init__(self, size: int = 64) -> None:
        self.size = size
        self.highest = -1
        self.seen: set[int] = set()

    def accept(self, seq: int) -> bool:
        if seq < 0:
            return False
        if seq in self.seen:
            return False
        if seq + self.size <= self.highest:
            return False
        self.seen.add(seq)
        if seq > self.highest:
            self.highest = seq
        cutoff = self.highest - self.size
        self.seen = {s for s in self.seen if s > cutoff}
        return True
