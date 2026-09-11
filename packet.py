# packet.py
# Packet model for NetRule simulation.
# NetRule Language Specification v1.0
#
# A Packet is a plain data object with exactly 5 fields.
# Packets are not defined in the NetRule language — they are provided
# externally (JSON file or interactive CLI).
#
# Field types at runtime:
#   source_ip        : str  (e.g. '10.0.0.5')
#   destination_ip   : str  (e.g. '10.0.0.20')
#   protocol         : str  ('TCP' | 'UDP' | 'ICMP')
#   source_port      : int  (0–65535)
#   destination_port : int  (0–65535)

import json


PROTOCOL_VALUES = {'TCP', 'UDP', 'ICMP'}


class PacketError(Exception):
    pass


class Packet:
    FIELDS = ('source_ip', 'destination_ip', 'protocol',
              'source_port', 'destination_port')

    def __init__(self, source_ip: str, destination_ip: str, protocol: str,
                 source_port: int, destination_port: int):
        self.source_ip        = source_ip
        self.destination_ip   = destination_ip
        self.protocol         = protocol.upper()
        self.source_port      = int(source_port)
        self.destination_port = int(destination_port)
        self._validate()

    def _validate(self):
        for ip_field in ('source_ip', 'destination_ip'):
            val = getattr(self, ip_field)
            parts = val.split('.')
            if len(parts) != 4:
                raise PacketError(f"{ip_field}: invalid IP address {val!r}")
            try:
                for p in parts:
                    v = int(p)
                    if not 0 <= v <= 255:
                        raise ValueError
            except ValueError:
                raise PacketError(f"{ip_field}: invalid IP address {val!r}")

        if self.protocol not in PROTOCOL_VALUES:
            raise PacketError(
                f"protocol: must be TCP, UDP, or ICMP; got {self.protocol!r}"
            )
        for port_field in ('source_port', 'destination_port'):
            v = getattr(self, port_field)
            if not 0 <= v <= 65535:
                raise PacketError(
                    f"{port_field}: must be 0–65535; got {v}"
                )

    def get(self, field: str):
        """Return the value of a named field (used by executor)."""
        return getattr(self, field, None)

    def display(self):
        w = 22
        print(f"  {'source_ip':<{w}} {self.source_ip}")
        print(f"  {'destination_ip':<{w}} {self.destination_ip}")
        print(f"  {'protocol':<{w}} {self.protocol}")
        print(f"  {'source_port':<{w}} {self.source_port}")
        print(f"  {'destination_port':<{w}} {self.destination_port}")

    @classmethod
    def from_dict(cls, d: dict) -> 'Packet':
        missing = [f for f in cls.FIELDS if f not in d]
        if missing:
            raise PacketError(f"Packet is missing fields: {missing}")
        return cls(
            source_ip        = d['source_ip'],
            destination_ip   = d['destination_ip'],
            protocol         = d['protocol'],
            source_port      = d['source_port'],
            destination_port = d['destination_port'],
        )

    @classmethod
    def from_json_file(cls, path: str) -> 'Packet':
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_interactive(cls) -> 'Packet':
        print("\n  Enter packet fields:")
        fields = {}
        prompts = [
            ('source_ip',        'Source IP (e.g. 10.0.0.5)'),
            ('destination_ip',   'Destination IP (e.g. 10.0.0.20)'),
            ('protocol',         'Protocol (TCP / UDP / ICMP)'),
            ('source_port',      'Source port (0-65535)'),
            ('destination_port', 'Destination port (0-65535)'),
        ]
        for key, label in prompts:
            val = input(f"  {label}: ").strip()
            fields[key] = val
        return cls.from_dict(fields)
