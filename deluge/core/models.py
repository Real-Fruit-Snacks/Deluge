from __future__ import annotations
from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Optional, Dict, Any, Union


class ScriptResult(BaseModel):
    id: str
    output: str
    data: Optional[Union[Dict[str, Any], List[Any]]] = Field(default_factory=dict)


class OSClass(BaseModel):
    type: str
    vendor: str
    osfamily: str
    osgen: Optional[str] = None
    accuracy: int
    cpes: List[str] = Field(default_factory=list)


class OSMatch(BaseModel):
    name: str
    accuracy: int
    classes: List[OSClass] = Field(default_factory=list)


class OSInfo(BaseModel):
    matches: List[OSMatch] = Field(default_factory=list)
    fingerprint: Optional[str] = None


class ServiceMetadata(BaseModel):
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    ostype: Optional[str] = None
    conf: Optional[int] = None
    method: Optional[str] = None
    tunnel: Optional[str] = None
    cpes: List[str] = Field(default_factory=list)


class Hop(BaseModel):
    ttl: int
    ipaddr: str
    rtt: Optional[float] = None
    host: Optional[str] = None


class Traceroute(BaseModel):
    port: Optional[int] = None
    proto: Optional[str] = None
    hops: List[Hop] = Field(default_factory=list)


class SSLCertificate(BaseModel):
    subject: Dict[str, str]
    issuer: Dict[str, str]
    pubkey: Dict[str, Any]  # type, bits, modulus, exponent
    validity: Dict[str, str]  # notBefore, notAfter
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    fingerprints: Dict[str, str] = Field(default_factory=dict)  # md5, sha1, sha256
    extensions: List[Any] = Field(default_factory=list)
    sig_algo: Optional[str] = None
    pem: str


class SSHHostKey(BaseModel):
    type: str
    bits: int
    fingerprint: str
    key: str


class PortInfo(BaseModel):
    portid: int
    protocol: str
    state: str
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None
    # Enhanced service data
    service: Optional[ServiceMetadata] = None
    # Structured scripts
    script_results: List[ScriptResult] = Field(default_factory=list)

    # Legacy fields (populated for backward compatibility)
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    scripts: Dict[str, str] = Field(default_factory=dict)


class HostInfo(BaseModel):
    address: IPvAnyAddress
    status: str
    hostnames: List[str] = Field(default_factory=list)
    ports: List[PortInfo] = Field(default_factory=list)

    # Enhanced OS data
    os: Optional[OSInfo] = None

    # Network Topology
    distance: Optional[int] = None
    traceroute: Optional[Traceroute] = None

    # Host-level scripts
    hostscript_results: List[ScriptResult] = Field(default_factory=list)

    # Legacy fields
    os_matches: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    nmap_version: str
    args: str
    start_time: str
    hosts: List[HostInfo] = Field(default_factory=list)
    elapsed_time: Optional[float] = None
    summary: Optional[str] = None
