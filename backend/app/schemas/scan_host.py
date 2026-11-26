"""Per-scan host snapshot: everything Nmap reported about one host in one scan.

Stored as JSON on `scan_hosts.details` and returned as-is by the API, so the
stored shape and the API contract are the same model.
"""

import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.parsers.models import ParsedHost

_MAX_SERVICES = 1000
_MAX_LIST = 50


class ServiceDetails(BaseModel):
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None = None
    version: str | None = None
    cpes: list[str] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)


class OsMatch(BaseModel):
    name: str
    accuracy: int | None = None
    cpes: list[str] = Field(default_factory=list)

    @field_validator("accuracy", mode="before")
    @classmethod
    def _accuracy(cls, value: object) -> int | None:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None


class TracerouteHop(BaseModel):
    ttl: str
    ipaddr: str | None = None
    rtt: str | None = None
    host: str | None = None


class ScanHostDetails(BaseModel):
    mac_address: str | None = None
    mac_vendor: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    os_matches: list[OsMatch] = Field(default_factory=list)
    uptime_seconds: int | None = None
    last_boot: str | None = None
    network_distance: int | None = None
    traceroute: list[TracerouteHop] = Field(default_factory=list)
    closed_port_count: int = 0
    filtered_port_count: int = 0
    services: list[ServiceDetails] = Field(default_factory=list)

    @classmethod
    def from_parsed_host(cls, host: ParsedHost) -> "ScanHostDetails":
        """Build the snapshot from parser output, bounding list sizes."""
        return cls(
            mac_address=host.mac_address,
            mac_vendor=host.mac_vendor,
            hostnames=[h["name"] for h in host.all_hostnames if h.get("name")][
                :_MAX_LIST
            ],
            os_matches=[OsMatch.model_validate(m) for m in host.os_matches[:_MAX_LIST]],
            uptime_seconds=host.uptime_seconds,
            last_boot=host.uptime_last_boot,
            network_distance=host.network_distance,
            traceroute=[
                TracerouteHop.model_validate(hop)
                for hop in host.traceroute_hops[:_MAX_LIST]
            ],
            closed_port_count=host.closed_port_count,
            filtered_port_count=host.filtered_port_count,
            services=[
                ServiceDetails(
                    port=s.port,
                    protocol=s.protocol,
                    state=s.state,
                    service_name=s.service_name,
                    product=s.product,
                    version=s.version,
                    cpes=s.cpes[:_MAX_LIST],
                    scripts=s.scripts,
                )
                for s in host.services[:_MAX_SERVICES]
            ],
        )


class ScanHostResponse(BaseModel):
    asset_id: uuid.UUID
    ipv4: str
    hostname: str | None = None
    operating_system: str | None = None
    details: ScanHostDetails

    model_config = ConfigDict(from_attributes=True)


class ScanHostListResponse(BaseModel):
    hosts: list[ScanHostResponse]
    total: int
