from dataclasses import dataclass, field
from .constants import MAX_TARGETS
@dataclass(frozen=True)
class ScanConfig:
    ports: tuple[int,...]
    workers:int=32
    ping_timeout_ms:int=1000
    port_timeout:float=1.0
    max_targets:int=MAX_TARGETS
@dataclass
class HostResult:
    ip:str
    ping_responded:bool=False
    ports:dict[int,str]=field(default_factory=dict)
    error:str|None=None
    @property
    def open_ports(self): return tuple(p for p,s in self.ports.items() if s=="open")
    # Legacy Persian label kept for backwards compatibility with old records.
    LEGACY_LABEL = "نامزد MikroTik"
    NEW_LABEL = "دستگاه MikroTik"
    @property
    def classification_label(self):
        """Persian label with the new wording ("دستگاه MikroTik")."""
        return {"mikrotik_candidate": self.NEW_LABEL}.get(self.classification, self.classification)
    @property
    def is_alive(self):
        """True if host answered ICMP or has any open TCP port."""
        return bool(self.ping_responded or self.open_ports)

    @property
    def classification(self):
        # Prefer port-based MikroTik detection even when ICMP is blocked.
        # Exclusive buckets so summary cards do not double-count hosts.
        open_8291 = self.ports.get(8291) == "open"
        open_8728 = self.ports.get(8728) == "open"
        if open_8291 and not open_8728:
            return "winbox_open_api_closed"
        if open_8291 or open_8728:
            return "mikrotik_candidate"
        if self.ping_responded or self.open_ports:
            return "potential_non_mikrotik"
        return "no_ping"
@dataclass
class ScanReport:
    records:list[HostResult]
    total_targets:int
    ping_responders:int
    completed:int
    errors:int=0
    canceled:bool=False
