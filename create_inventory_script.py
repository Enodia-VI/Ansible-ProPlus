#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
import unicodedata
import pycountry


from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

DEFAULT_API_URL = "https://******"

DEFAULT_TTL_SECONDS = 24 * 60 * 60

DEFAULT_TIMEOUT_SECONDS = 15

DEFAULT_CURRENT_FILE = Path(
    "inventory/generated/network.yml"
)

DEFAULT_METADATA_FILE = Path(
    "inventory/generated/metadata.json"
)

DEFAULT_SNAPSHOT_DIR = Path(
    "inventory/snapshots"
)

# =============================================================================
# Environment configuration
# =============================================================================

API_KEY = os.getenv("NETWORK_API_KEY")

API_URL = os.getenv(
    "NETWORK_API_URL_TYPE_1",
    DEFAULT_API_URL,
)

TTL_SECONDS = int(
    os.getenv(
        "NETWORK_INVENTORY_TTL",
        DEFAULT_TTL_SECONDS,
    )
)

GENERATOR_VERSION = "1.0.0"


# =============================================================================
# API-specific mappings
# =============================================================================

# Adapt this mapping to the real values returned by your API.
TYPE_MAP: dict[int, str] = {
    1: "dns",
    2: "router",
    3: "switch",
    4: "firewall",
}


# =============================================================================
# Exceptions
# =============================================================================

class InventoryError(Exception):
    """Base exception for inventory generation."""


class APIError(InventoryError):
    """Raised when the API request fails."""


class InventoryValidationError(InventoryError):
    """Raised when API data cannot be safely normalized."""


# =============================================================================
# Canonical internal model
# =============================================================================

@dataclass(frozen=True)
class NormalizedNode:
    # Identity
    node_id: int
    name: str
    active: bool

    # Network
    ipv4: str | None
    ipv6: str | None
    lan_ip: str | None

    # Cluster / infrastructure
    cluster_id: int
    cluster_name: str
    carrier: str 
    carrier_slug: str
    max_qps: int

    # Location
    location_id: int
    continent: str
    continent_slug: str
    country: str
    country_slug: str
    city: str
    city_slug: str
    site: str

    # Device
    device_type: str


# =============================================================================
# General helpers
# =============================================================================

def country_name_from_code(code: str) -> str:
    country = pycountry.countries.get(
        alpha_2=code.upper()
    )

    if country is None:
        raise InventoryValidationError(
            f"Unknown country code: {code!r}"
        )

    return country.name

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_identifier(value: str) -> str:
    """
    Convert human-readable values into safe group identifiers.

    Examples:
        "Nord America" -> "nord_america"
        "DataPacket"   -> "datapacket"
        "New York"     -> "new_york"
    """

    value = unicodedata.normalize("NFKD", value)
    value = value.encode("ascii", "ignore").decode("ascii")
    value = value.lower()

    value = re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    )

    value = re.sub(
        r"_+",
        "_",
        value,
    )

    return value.strip("_")


def require_dict(
    value: Any,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryValidationError(
            f"Field '{field}' must be an object"
        )

    return value


def require_string(
    value: Any,
    field: str,
) -> str:

    if not isinstance(value, str) or not value.strip():
        raise InventoryValidationError(
            f"Field '{field}' must be a non-empty string"
        )

    return value.strip()


def slugify_or_raise(value: str, field: str) -> str:
    """Versione slug di un valore leggibile, per i nomi di gruppo Ansible."""

    slug = normalize_identifier(value)

    if not slug:
        raise InventoryValidationError(
            f"Field '{field}' cannot be normalized into a valid identifier: {value!r}"
        )

    return slug


def require_int(
    value: Any,
    field: str,
    *,
    minimum: int | None = None,
) -> int:

    if isinstance(value, bool) or not isinstance(value, int):
        raise InventoryValidationError(
            f"Field '{field}' must be an integer"
        )

    if minimum is not None and value < minimum:
        raise InventoryValidationError(
            f"Field '{field}' must be >= {minimum}"
        )

    return value


def require_bool(
    value: Any,
    field: str,
) -> bool:

    if not isinstance(value, bool):
        raise InventoryValidationError(
            f"Field '{field}' must be boolean"
        )

    return value


def validate_ip(
    value: Any,
    field: str,
    *,
    version: int,
) -> str | None:

    if value is None or value == "":
        return None

    if not isinstance(value, str):
        raise InventoryValidationError(
            f"Field '{field}' must be a string"
        )

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InventoryValidationError(
            f"Field '{field}' contains invalid IP address: {value!r}"
        ) from exc

    if address.version != version:
        raise InventoryValidationError(
            f"Field '{field}' expected IPv{version}: {value!r}"
        )

    return str(address)

# ====================================================================
# Inventory validation before sending to remote VM
# ====================================================================

def validate_inventory(
    inventory: dict[str, Any],
) -> None:

    if not isinstance(inventory, dict):
        raise InventoryValidationError(
            "Generated inventory must be an object"
        )

    all_group = inventory.get("all")

    if not isinstance(all_group, dict):
        raise InventoryValidationError(
            "Generated inventory is missing 'all'"
        )

    hosts = all_group.get("hosts")

    if not isinstance(hosts, dict):
        raise InventoryValidationError(
            "Generated inventory is missing 'all.hosts'"
        )

    if not hosts:
        raise InventoryValidationError(
            "Generated inventory contains zero hosts"
        )

    for host_name, host_vars in hosts.items():

        if not isinstance(host_name, str) or not host_name:
            raise InventoryValidationError(
                "Generated inventory contains an invalid host name"
            )

        if not isinstance(host_vars, dict):
            raise InventoryValidationError(
                f"Host {host_name!r} variables must be an object"
            )

        ansible_host = host_vars.get("ansible_host")

        if not ansible_host:
            raise InventoryValidationError(
                f"Host {host_name!r} has no ansible_host"
            )


# =============================================================================
# API client
# =============================================================================

class NetworkAPIClient:

    def __init__(
        self,
        url: str,
        timeout: int,
    ) -> None:

        self.url = url
        self.timeout = timeout

        if not API_KEY:
            raise APIError(
                "NETWORK_API_KEY is not set"
            )

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Authorization": f"Bearer {API_KEY}",
                "Accept": "application/json",
            }
        )

    def fetch_nodes(self) -> list[dict[str, Any]]:

        try:
            response = self.session.get(
                self.url,
                timeout=self.timeout,
            )

        except requests.RequestException as exc:
            raise APIError(
                f"API request failed: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise APIError(
                f"API authentication failed: HTTP {response.status_code}"
            )

        try:
            response.raise_for_status()

        except requests.HTTPError as exc:
            raise APIError(
                f"API returned HTTP {response.status_code}"
            ) from exc

        try:
            data = response.json()

        except ValueError as exc:
            raise APIError(
                "API returned invalid JSON"
            ) from exc

        if not isinstance(data, list):
            raise APIError(
                "API response must be a JSON array"
            )

        return data


# =============================================================================
# Normalization
# =============================================================================

def normalize_node(
    raw: dict[str, Any],
) -> NormalizedNode:

    node = require_dict(
        raw,
        "node",
    )

    # -------------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------------

    node_id = require_int(
        node.get("id"),
        "id",
        minimum=1,
    )

    name = require_string(
        node.get("name"),
        "name",
    )

    if any(char.isspace() for char in name):
        raise InventoryValidationError(
            f"Node name cannot contain whitespace: {name!r}"
        )

    active = require_bool(
        node.get("active"),
        "active",
    )

    # -------------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------------

    ipv4 = validate_ip(
        node.get("ipv4_ip"),
        "ipv4_ip",
        version=4,
    )

    ipv6 = validate_ip(
        node.get("ipv6_ip"),
        "ipv6_ip",
        version=6,
    )

    lan_ip = validate_ip(
        node.get("lan_ip"),
        "lan_ip",
        version=4,
    )

    if not ipv4 and not ipv6:
        raise InventoryValidationError(
            f"Node {name!r} has neither IPv4 nor IPv6"
        )

    # -------------------------------------------------------------------------
    # Infrastructure
    # -------------------------------------------------------------------------

    max_qps = require_int(
        node.get("max_qps"),
        "max_qps",
        minimum=0,
    )

    cluster = require_dict(
        node.get("cluster"),
        "cluster",
    )

    cluster_id = require_int(
        cluster.get("id"),
        "cluster.id",
        minimum=1,
    )

    cluster_name = require_string(
        cluster.get("name"),
        "cluster.name",
    )

    carrier = require_string(
        cluster.get("carrier"),
        "cluster.carrier",
    )
    carrier_slug = slugify_or_raise(carrier, "cluster.carrier")

    # -------------------------------------------------------------------------
    # Location
    # -------------------------------------------------------------------------

    location = require_dict(
        cluster.get("location"),
        "cluster.location",
    )

    location_id = require_int(
        location.get("id"),
        "cluster.location.id",
        minimum=1,
    )

    continent = require_string(
        location.get("continent"),
        "cluster.location.continent",
    )
    continent_slug = slugify_or_raise(continent, "cluster.location.continent")

    country_code = require_string(
        location.get("country"),
        "cluster.location.country",
    ).upper()

    country = country_name_from_code(country_code)
    country_slug = slugify_or_raise(country, "cluster.location.country")

    city = require_string(
        location.get("city"),
        "cluster.location.city",
    )
    city_slug = slugify_or_raise(city, "cluster.location.city")

    site = require_string(
        location.get("name"),
        "cluster.location.name",
    )

    # -------------------------------------------------------------------------
    # Device type
    # -------------------------------------------------------------------------

    raw_type = require_int(
        node.get("type"),
        "type",
        minimum=0,
    )

    if raw_type not in TYPE_MAP:
        raise InventoryValidationError(
            f"Node {name!r}: unknown device type {raw_type}"
        )

    device_type = TYPE_MAP[raw_type]

    return NormalizedNode(
        node_id=node_id,
        name=name,
        active=active,

        ipv4=ipv4,
        ipv6=ipv6,
        lan_ip=lan_ip,

        cluster_id=cluster_id,
        cluster_name=cluster_name,
        carrier=carrier,
        carrier_slug=carrier_slug,
        max_qps=max_qps,

        location_id=location_id,
        continent=continent,
        continent_slug=continent_slug,
        country=country,
        country_slug=country_slug,
        city=city,
        city_slug=city_slug,
        site=site,

        device_type=device_type,
    )


def normalize_nodes(
    raw_nodes: list[dict[str, Any]],
) -> list[NormalizedNode]:

    if not raw_nodes:
        raise InventoryValidationError(
            "API returned zero nodes"
        )

    normalized: list[NormalizedNode] = []

    seen_ids: set[int] = set()
    seen_names: set[str] = set()

    for index, raw_node in enumerate(raw_nodes):

        try:
            node = normalize_node(raw_node)

        except InventoryValidationError as exc:
            raise InventoryValidationError(
                f"Invalid node at API index {index}: {exc}"
            ) from exc

        if node.node_id in seen_ids:
            raise InventoryValidationError(
                f"Duplicate node ID: {node.node_id}"
            )

        if node.name in seen_names:
            raise InventoryValidationError(
                f"Duplicate node name: {node.name!r}"
            )

        seen_ids.add(node.node_id)
        seen_names.add(node.name)

        normalized.append(node)

    return normalized


# =============================================================================
# Inventory groups
# =============================================================================

def add_host_to_group(
    groups: dict[str, dict[str, Any]],
    group_name: str,
    host_name: str,
) -> None:

    group = groups.setdefault(
        group_name,
        {},
    )

    hosts = group.setdefault(
        "hosts",
        {},
    )

    hosts.setdefault(
        host_name,
        {},
    )


def make_site_group(
    node: NormalizedNode,
) -> str:

    site_slug = normalize_identifier(
        node.site
    )

    return (
        f"site_{site_slug}"
    )


# =============================================================================
# Geographic hierarchy
# =============================================================================

def build_geographic_groups(
    groups: dict[str, dict[str, Any]],
    nodes: list[NormalizedNode],
) -> None:

    for node in nodes:

        continent_group = (
            f"continent_{node.continent_slug}"
        )

        country_group = (
            f"country_{node.country_slug}"
        )

        site_group = make_site_group(node)

        # ================================================================
        # CONTINENT
        # ================================================================

        continent = groups.setdefault(
            continent_group,
            {},
        )

        continent_children = continent.setdefault(
            "children",
            {},
        )

        # ================================================================
        # COUNTRY
        # ================================================================

        country = continent_children.setdefault(
            country_group,
            {},
        )

        country_children = country.setdefault(
            "children",
            {},
        )

        # ================================================================
        # SITE
        # ================================================================

        site = country_children.setdefault(
            site_group,
            {},
        )

        site_hosts = site.setdefault(
            "hosts",
            {},
        )

        site_hosts.setdefault(
            node.name,
            {},
        )


# =============================================================================
# Inventory renderer
# =============================================================================

def build_inventory(
    nodes: list[NormalizedNode],
) -> dict[str, Any]:

    hosts: dict[str, dict[str, Any]] = {}
    groups: dict[str, dict[str, Any]] = {}

    # =========================================================================
    # HOST VARIABLES
    # =========================================================================

    for node in nodes:

        host_vars = {
            "node_id": node.node_id,
            "active": node.active,
            "device_type": node.device_type,

            "ansible_host": (
                node.ipv4
                or node.ipv6
            ),

            "ipv4": node.ipv4,
            "ipv6": node.ipv6,
            "lan_ip": node.lan_ip,

            "cluster_id": node.cluster_id,
            "cluster_name": node.cluster_name,
            "carrier": node.carrier,
            "max_qps": node.max_qps,

            "location_id": node.location_id,
            "continent": node.continent,
            "country": node.country,
            "city": node.city,
            "site": node.site,
        }

        hosts[node.name] = host_vars

    # =========================================================================
    # TECHNICAL GROUPS
    # =========================================================================

    for node in nodes:
        
        # Device type
        add_host_to_group(
            groups,
            f"type_{node.device_type}",
            node.name,
        )

        # Carrier
        add_host_to_group(
            groups,
            f"carrier_{node.carrier_slug}",
            node.name,
        )

        # Cluster
        add_host_to_group(
            groups,
            f"cluster_{node.cluster_id}",
            node.name,
        )

        # IPv4 / IPv6 capabilities
        if node.ipv4:
            add_host_to_group(
                groups,
                "ipv4",
                node.name,
            )

        if node.ipv6:
            add_host_to_group(
                groups,
                "ipv6",
                node.name,
            )

        # Status
        if node.active:
            add_host_to_group(
                groups,
                "active",
                node.name,
            )
        else:
            add_host_to_group(
                groups,
                "inactive",
                node.name,
            )

    # =========================================================================
    # GEOGRAPHIC GROUPS
    # =========================================================================

    build_geographic_groups(
        groups,
        nodes,
    )

    # =========================================================================
    # Final inventory
    # =========================================================================

    return {
        "all": {
            "children": groups,
            "hosts": hosts,
        }
    }


def load_metadata(
    path: Path,
) -> dict[str, Any] | None:

    if not path.exists():
        return None

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None


def snapshot_is_valid(
    current_path: Path,
    metadata_path: Path,
    ttl_seconds: int,
) -> bool:

    if not current_path.exists():
        return False

    metadata = load_metadata(
        metadata_path
    )

    if not metadata:
        return False

    generated_at_raw = metadata.get(
        "generated_at"
    )

    if not isinstance(
        generated_at_raw,
        str,
    ):
        return False

    try:
        generated_at = datetime.fromisoformat(
            generated_at_raw.replace(
                "Z",
                "+00:00",
            )
        )

    except ValueError:
        return False

    age = (
        utc_now() - generated_at
    ).total_seconds()

    return age < ttl_seconds


# =============================================================================
# Atomic writes
# =============================================================================

def atomic_write(
    path: Path,
    content: str,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as temp_file:

        temp_file.write(content)

        temporary_path = Path(
            temp_file.name
        )

    temporary_path.replace(
        path
    )


def write_yaml(
    path: Path,
    inventory: dict[str, Any],
    generated_at: datetime,
    node_count: int,
) -> None:

    header = (
        "# ============================================================\n"
        "# GENERATED FILE - DO NOT EDIT MANUALLY\n"
        "#\n"
        f"# Generator version : {GENERATOR_VERSION}\n"
        f"# Generated         : {isoformat(generated_at)}\n"
        f"# Nodes             : {node_count}\n"
        "# Source            : Network Inventory API\n"
        "#\n"
        "# Gruppi disponibili per 'target_group' nel playbook:\n"
        "#   type_<device_type>    es. type_router, type_dns\n"
        "#   carrier_<carrier>     es. carrier_datapacket\n"
        "#   cluster_<cluster_id>  es. cluster_1\n"
        "#   continent_<slug>      es. continent_nord_america\n"
        "#   country_<slug>        es. country_italy\n"
        "#   site_<slug>           es. site_los_angeles_dc1\n"
        "#   ipv4 / ipv6           nodi con quella famiglia di indirizzi\n"
        "#   active / inactive     stato del nodo\n"
        "# ============================================================\n"
        "\n"
    )

    content = header + yaml.safe_dump(
        inventory,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    atomic_write(
        path,
        content,
    )


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:

    content = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    atomic_write(
        path,
        content,
    )


# =============================================================================
# Snapshot handling
# =============================================================================

def write_snapshot(
    inventory: dict[str, Any],
    snapshot_dir: Path,
    generated_at: datetime,
    node_count: int,
) -> Path:

    snapshot_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = generated_at.strftime(
        "%Y%m%d_%H%M%S"
    )

    snapshot_path = (
        snapshot_dir
        / f"network_{timestamp}.yml"
    )

    write_yaml(
        snapshot_path,
        inventory,
        generated_at,
        node_count,
    )

    return snapshot_path


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Generate a static Ansible inventory "
            "from the Network Inventory API"
        )
    )

    parser.add_argument(
        "--api-url",
        default=API_URL,
        help="Network Inventory API URL",
    )

    parser.add_argument(
        "--ttl",
        type=int,
        default=TTL_SECONDS,
        help="Inventory TTL in seconds",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="HTTP request timeout",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force refresh even if current inventory is valid",
    )

    parser.add_argument(
        "--current",
        type=Path,
        default=DEFAULT_CURRENT_FILE,
        help="Current inventory file",
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_FILE,
        help="Inventory metadata file",
    )

    parser.add_argument(
        "--snapshots",
        type=Path,
        default=DEFAULT_SNAPSHOT_DIR,
        help="Historical snapshots directory",
    )

    return parser.parse_args()


# =============================================================================
# Main
# =============================================================================

def main() -> int:

    args = parse_args()

    # =========================================================================
    # 1. Check TTL
    # =========================================================================

    if not args.force:

        if snapshot_is_valid(
            current_path=args.current,
            metadata_path=args.metadata,
            ttl_seconds=args.ttl,
        ):

            metadata = load_metadata(
                args.metadata
            ) or {}

            print(
                "Inventory snapshot is still valid."
            )

            print(
                f"Generated : {metadata.get('generated_at')}"
            )

            print(
                f"Expires   : {metadata.get('expires_at')}"
            )

            print(
                f"Nodes     : {metadata.get('node_count')}"
            )

            print(
                f"Inventory : {args.current}"
            )

            return 0

    print(
        "Refreshing inventory from API..."
    )

    try:

        # ================================================================
        # API
        # ================================================================

        client = NetworkAPIClient(
            url=args.api_url,
            timeout=args.timeout,
        )

        raw_nodes = client.fetch_nodes()

        print(
            f"API returned {len(raw_nodes)} nodes."
        )

        # ================================================================
        # Normalize + validate
        # ================================================================

        nodes = normalize_nodes(
            raw_nodes
        )

        print(
            f"Successfully validated {len(nodes)} nodes."
        )

        # ================================================================
        # Build inventory
        # ================================================================

        inventory = build_inventory(
            nodes
        )

        generated_at = utc_now()

        # ================================================================
        # Historical snapshot
        # ================================================================

        snapshot_path = write_snapshot(
            inventory=inventory,
            snapshot_dir=args.snapshots,
            generated_at=generated_at,
            node_count=len(nodes),
        )

        # ================================================================
        # Metadata
        # ================================================================

        expires_at = (
            generated_at
            + timedelta(
                seconds=args.ttl
            )
        )

        metadata = {
            "generator_version": GENERATOR_VERSION,
            "generated_at": isoformat(
                generated_at
            ),
            "expires_at": isoformat(
                expires_at
            ),
            "node_count": len(nodes),
            "source": args.api_url,
            "current_inventory": str(
                args.current
            ),
            "snapshot": str(
                snapshot_path
            ),
        }

        # ================================================================
        # Current inventory
        # ================================================================

        write_yaml(
            path=args.current,
            inventory=inventory,
            generated_at=generated_at,
            node_count=len(nodes),
        )

        write_json(
            path=args.metadata,
            data=metadata,
        )

    except InventoryError as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        print(
            "Existing inventory was NOT modified.",
            file=sys.stderr,
        )

        return 1

    except Exception as exc:

        print(
            f"UNEXPECTED ERROR: {exc}",
            file=sys.stderr,
        )

        print(
            "Existing inventory was NOT modified.",
            file=sys.stderr,
        )

        return 2

    # =========================================================================
    # 3. Success
    # =========================================================================

    print()
    print(
        "Inventory successfully updated."
    )

    print(
        f"Current  : {args.current}"
    )

    print(
        f"Snapshot : {snapshot_path}"
    )

    print(
        f"Metadata : {args.metadata}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )