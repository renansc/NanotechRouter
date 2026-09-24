import os
import re
import json
import ipaddress
import subprocess
import signal

from flask import Flask, jsonify, request

app = Flask(__name__)

BASE = "/opt/linux-router"
DATA = BASE + "/data"
CONFIG = BASE + "/config"

STATE_FILE = DATA + "/router_state.json"

os.makedirs(DATA, exist_ok=True)
os.makedirs(CONFIG + "/dnsmasq", exist_ok=True)
os.makedirs(CONFIG + "/nftables", exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def run(cmd, timeout=15):

    try:

        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            "success": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip()
        }

    except Exception as e:

        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e)
        }


def load_state():

    if not os.path.exists(STATE_FILE):

        return {
            "wan": None,
            "lans": {}
        }

    try:

        with open(STATE_FILE) as f:
            return json.load(f)

    except Exception:

        return {
            "wan": None,
            "lans": {}
        }


def save_state(state):

    tmp = STATE_FILE + ".tmp"

    with open(tmp, "w") as f:
        json.dump(
            state,
            f,
            indent=4
        )

    os.replace(
        tmp,
        STATE_FILE
    )


def valid_interface(name):

    if not name:
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,32}",
            name
        )
    )


def interface_exists(name):

    return os.path.exists(
        "/sys/class/net/" + name
    )


def interface_ipv4(name):

    result = run([
        "ip",
        "-j",
        "-4",
        "addr",
        "show",
        "dev",
        name
    ])

    if not result["success"]:
        return []

    try:

        data = json.loads(
            result["stdout"]
        )

    except Exception:
        return []

    addresses = []

    for iface in data:

        for addr in iface.get(
            "addr_info",
            []
        ):

            if addr.get("family") == "inet":

                addresses.append(
                    str(addr["local"]) +
                    "/" +
                    str(addr["prefixlen"])
                )

    return addresses


def get_default_route():

    result = run([
        "ip",
        "-j",
        "route",
        "show",
        "default"
    ])

    if not result["success"]:
        return []

    try:
        return json.loads(
            result["stdout"]
        )
    except Exception:
        return []


# ============================================================
# INTERFACES
# ============================================================

def get_interfaces():

    result = run([
        "ip",
        "-j",
        "addr",
        "show"
    ])

    if not result["success"]:
        return []

    try:

        raw = json.loads(
            result["stdout"]
        )

    except Exception:
        return []

    state = load_state()

    routes = get_default_route()

    interfaces = []

    for iface in raw:

        name = iface.get("ifname")

        if name == "lo":
            continue

        addresses = []

        for addr in iface.get(
            "addr_info",
            []
        ):

            if addr.get("family") == "inet":

                addresses.append(
                    str(addr.get("local")) +
                    "/" +
                    str(addr.get("prefixlen"))
                )

        gateway = None

        for route in routes:

            if route.get("dev") == name:
                gateway = route.get("gateway")

        speed = None

        try:

            with open(
                f"/sys/class/net/{name}/speed"
            ) as f:

                value = f.read().strip()

                if value.isdigit():
                    speed = int(value)

        except Exception:
            pass

        role = "LIVRE"

        if state.get("wan") == name:
            role = "WAN"

        elif name in state.get("lans", {}):
            role = "LAN"

        if "." in name:
            iface_type = "VLAN"

        elif name.startswith("docker"):
            iface_type = "DOCKER"

        elif name.startswith("br-"):
            iface_type = "BRIDGE"

        elif name.startswith("veth"):
            iface_type = "VIRTUAL"

        else:
            iface_type = "PHYSICAL"

        interfaces.append({
            "name": name,
            "state": iface.get(
                "operstate",
                "UNKNOWN"
            ),
            "mac": iface.get(
                "address",
                ""
            ),
            "mtu": iface.get(
                "mtu",
                0
            ),
            "addresses": addresses,
            "gateway": gateway,
            "speed": speed,
            "role": role,
            "type": iface_type
        })

    return interfaces


# ============================================================
# NAT
# ============================================================

def rebuild_nat():

    state = load_state()

    wan = state.get("wan")

    if not wan:
        return {
            "success": False,
            "message": "Nenhuma WAN configurada."
        }

    if not interface_exists(wan):

        return {
            "success": False,
            "message": "Interface WAN não existe."
        }

    run([
        "nft",
        "delete",
        "table",
        "ip",
        "linux_router_nat"
    ])

    result = run([
        "nft",
        "add",
        "table",
        "ip",
        "linux_router_nat"
    ])

    if not result["success"]:

        return result

    result = run([
        "nft",
        "add",
        "chain",
        "ip",
        "linux_router_nat",
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "100",
        ";",
        "policy",
        "accept",
        ";",
        "}"
    ])

    if not result["success"]:
        return result

    for interface, lan in state.get(
        "lans",
        {}
    ).items():

        if not lan.get(
            "internet",
            False
        ):
            continue

        try:

            network = str(
                ipaddress.ip_interface(
                    lan["address"]
                ).network
            )

        except Exception:
            continue

        result = run([
            "nft",
            "add",
            "rule",
            "ip",
            "linux_router_nat",
            "postrouting",
            "oifname",
            wan,
            "ip",
            "saddr",
            network,
            "masquerade"
        ])

        if not result["success"]:
            return result

    return {
        "success": True,
        "message": "NAT atualizado."
    }



# ============================================================
# FORWARD / DOCKER
# ============================================================

def rebuild_forward():

    """
    Libera o encaminhamento das LANs gerenciadas para a WAN.

    Docker normalmente utiliza:
        FORWARD policy DROP

    Portanto as regras do Router Manager são inseridas na
    chain DOCKER-USER, que é processada antes das regras
    principais do Docker.

    IMPORTANTE:
    somente regras marcadas com comentário linux-router
    são removidas/recriadas.
    """

    state = load_state()

    wan = state.get("wan")

    if not wan:

        return {
            "success": False,
            "message": "Nenhuma WAN configurada."
        }

    if not interface_exists(wan):

        return {
            "success": False,
            "message": "Interface WAN não existe."
        }

    # IPv4 forwarding
    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])

    #
    # Verifica se DOCKER-USER existe.
    #

    check = run([
        "iptables",
        "-nL",
        "DOCKER-USER"
    ])

    if not check["success"]:

        return {
            "success": False,
            "message":
                "Chain DOCKER-USER não encontrada."
        }

    #
    # Remove somente regras criadas pelo Linux Router.
    #
    # Fazemos repetidamente porque os números das regras
    # mudam depois de cada remoção.
    #

    while True:

        listing = run([
            "iptables",
            "-L",
            "DOCKER-USER",
            "-n",
            "--line-numbers"
        ])

        if not listing["success"]:
            break

        rule_number = None

        for line in listing["stdout"].splitlines():

            if "linux-router" not in line:
                continue

            parts = line.split()

            if parts and parts[0].isdigit():
                rule_number = parts[0]
                break

        if not rule_number:
            break

        run([
            "iptables",
            "-D",
            "DOCKER-USER",
            rule_number
        ])

    #
    # Para cada LAN com Internet:
    #
    # LAN -> WAN
    # WAN -> LAN (somente retorno)
    #

    position = 1

    for interface, lan in state.get(
        "lans",
        {}
    ).items():

        if not lan.get(
            "internet",
            False
        ):
            continue

        if not interface_exists(interface):
            continue

        #
        # LAN -> WAN
        #

        result = run([
            "iptables",
            "-I",
            "DOCKER-USER",
            str(position),
            "-i",
            interface,
            "-o",
            wan,
            "-m",
            "comment",
            "--comment",
            "linux-router",
            "-j",
            "ACCEPT"
        ])

        if not result["success"]:

            return {
                "success": False,
                "message":
                    "Erro criando FORWARD "
                    + interface
                    + " -> "
                    + wan
                    + ": "
                    + result["stderr"]
            }

        position += 1

        #
        # WAN -> LAN
        # Somente conexões já estabelecidas.
        #

        result = run([
            "iptables",
            "-I",
            "DOCKER-USER",
            str(position),
            "-i",
            wan,
            "-o",
            interface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            "linux-router",
            "-j",
            "ACCEPT"
        ])

        if not result["success"]:

            return {
                "success": False,
                "message":
                    "Erro criando retorno FORWARD "
                    + wan
                    + " -> "
                    + interface
                    + ": "
                    + result["stderr"]
            }

        position += 1

    return {
        "success": True,
        "message": "FORWARD atualizado."
    }


def rebuild_network_rules():

    """
    Atualiza em conjunto:
      - IPv4 forwarding
      - NAT
      - FORWARD

    Deve ser chamado sempre que WAN/LAN mudar.
    """

    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])

    nat_result = rebuild_nat()

    forward_result = rebuild_forward()

    return {
        "nat": nat_result,
        "forward": forward_result
    }



# ============================================================
# DHCP
# ============================================================

def stop_dhcp(interface):

    pidfile = (
        "/run/linux-router/"
        + interface
        + ".dnsmasq.pid"
    )

    if os.path.exists(pidfile):

        try:

            with open(pidfile) as f:
                pid = int(f.read().strip())

            os.kill(
                pid,
                signal.SIGTERM
            )

        except Exception:
            pass

        try:
            os.remove(pidfile)
        except Exception:
            pass


def start_dhcp(
    interface,
    gateway,
    start,
    end,
    dns
):

    stop_dhcp(interface)

    conf = (
        CONFIG
        + "/dnsmasq/"
        + interface
        + ".conf"
    )

    pidfile = (
        "/run/linux-router/"
        + interface
        + ".dnsmasq.pid"
    )

    leasefile = (
        DATA
        + "/"
        + interface
        + ".leases"
    )

    content = f"""
interface={interface}
bind-interfaces
except-interface=lo
dhcp-range={start},{end},255.255.255.0,12h
dhcp-option=3,{gateway}
dhcp-option=6,{dns}
dhcp-authoritative
dhcp-leasefile={leasefile}
pid-file={pidfile}
"""

    with open(conf, "w") as f:
        f.write(content)

    test = run([
        "dnsmasq",
        "--test",
        "--conf-file=" + conf
    ])

    if not test["success"]:

        return {
            "success": False,
            "message": test["stderr"]
        }

    result = run([
        "dnsmasq",
        "--conf-file=" + conf
    ])

    if not result["success"]:

        return {
            "success": False,
            "message": result["stderr"]
        }

    return {
        "success": True
    }



# ============================================================
# PORT ALIASES / DEVICE NAMES
# ============================================================

ALIASES_FILE = DATA + "/port_aliases.json"
DEVICE_NAMES_FILE = DATA + "/device_names.json"


def load_json_file(path, default):

    if not os.path.exists(path):
        return default

    try:

        with open(path) as f:
            data = json.load(f)

        return data

    except Exception:
        return default


def save_json_file(path, data):

    tmp = path + ".tmp"

    with open(tmp, "w") as f:

        json.dump(
            data,
            f,
            indent=4
        )

    os.replace(
        tmp,
        path
    )


def get_aliases():

    return load_json_file(
        ALIASES_FILE,
        {}
    )


def get_device_names():

    return load_json_file(
        DEVICE_NAMES_FILE,
        {}
    )


def normalize_mac(mac):

    if not mac:
        return ""

    return mac.lower().strip()


# ============================================================
# NEIGHBORS
# ============================================================

def get_neighbors():

    result = run([
        "ip",
        "-j",
        "neigh",
        "show"
    ])

    if not result["success"]:
        return []

    try:

        raw = json.loads(
            result["stdout"]
        )

    except Exception:
        return []

    devices = []

    for item in raw:

        ip = item.get("dst", "")
        mac = normalize_mac(
            item.get("lladdr", "")
        )

        interface = item.get(
            "dev",
            ""
        )

        state = item.get(
            "state",
            []
        )

        if isinstance(state, list):
            state = ",".join(state)

        if not ip:
            continue

        # Ignora IPv6 nesta tela por enquanto
        try:

            addr = ipaddress.ip_address(ip)

            if addr.version != 4:
                continue

        except Exception:
            continue

        devices.append({
            "ip": ip,
            "mac": mac,
            "interface": interface,
            "neighbor_state": state
        })

    return devices


# ============================================================
# DHCP LEASES - TODAS AS LANS
# ============================================================

def get_dhcp_devices():

    state = load_state()

    result = []

    for interface in state.get(
        "lans",
        {}
    ):

        leasefile = (
            DATA
            + "/"
            + interface
            + ".leases"
        )

        if not os.path.exists(
            leasefile
        ):
            continue

        try:

            with open(leasefile) as f:

                for line in f:

                    parts = line.split()

                    if len(parts) < 3:
                        continue

                    expires = parts[0]
                    mac = normalize_mac(
                        parts[1]
                    )
                    ip = parts[2]

                    hostname = ""

                    if len(parts) >= 4:

                        if parts[3] != "*":
                            hostname = parts[3]

                    result.append({
                        "expires": expires,
                        "mac": mac,
                        "ip": ip,
                        "hostname": hostname,
                        "interface": interface
                    })

        except Exception:
            pass

    return result


# ============================================================
# MERGE DHCP + NEIGHBOR
# ============================================================

def build_device_list():

    aliases = get_aliases()
    custom_names = get_device_names()

    dhcp = get_dhcp_devices()
    neighbors = get_neighbors()

    devices = {}

    #
    # Primeiro DHCP
    #

    for item in dhcp:

        mac = item.get("mac", "")
        ip = item.get("ip", "")

        key = mac if mac else (
            item.get("interface", "")
            + ":"
            + ip
        )

        devices[key] = {
            "ip": ip,
            "mac": mac,
            "hostname":
                item.get(
                    "hostname",
                    ""
                ),
            "interface":
                item.get(
                    "interface",
                    ""
                ),
            "source": "DHCP",
            "online": False,
            "neighbor_state": "",
            "expires":
                item.get(
                    "expires",
                    ""
                )
        }

    #
    # Agora ARP / ip neigh
    #

    for item in neighbors:

        mac = item.get("mac", "")
        ip = item.get("ip", "")

        key = mac if mac else (
            item.get("interface", "")
            + ":"
            + ip
        )

        if key in devices:

            devices[key]["online"] = True

            devices[key][
                "neighbor_state"
            ] = item.get(
                "neighbor_state",
                ""
            )

            if (
                not devices[key].get(
                    "interface"
                )
            ):
                devices[key][
                    "interface"
                ] = item.get(
                    "interface",
                    ""
                )

            devices[key][
                "source"
            ] = "DHCP + ARP"

        else:

            devices[key] = {
                "ip": ip,
                "mac": mac,
                "hostname": "",
                "interface":
                    item.get(
                        "interface",
                        ""
                    ),
                "source": "ARP",
                "online": True,
                "neighbor_state":
                    item.get(
                        "neighbor_state",
                        ""
                    ),
                "expires": ""
            }

    #
    # Informações adicionais
    #

    final = []

    for device in devices.values():

        mac = normalize_mac(
            device.get(
                "mac",
                ""
            )
        )

        interface = device.get(
            "interface",
            ""
        )

        custom_name = custom_names.get(
            mac,
            ""
        )

        hostname = device.get(
            "hostname",
            ""
        )

        if custom_name:
            display_name = custom_name

        elif hostname:
            display_name = hostname

        else:
            display_name = "Desconhecido"

        device[
            "custom_name"
        ] = custom_name

        device[
            "display_name"
        ] = display_name

        device[
            "port_alias"
        ] = aliases.get(
            interface,
            ""
        )

        final.append(
            device
        )

    #
    # Online primeiro, depois IP
    #

    def sort_ip(item):

        try:
            ipnum = int(
                ipaddress.ip_address(
                    item.get(
                        "ip",
                        "0.0.0.0"
                    )
                )
            )

        except Exception:
            ipnum = 0

        return (
            0 if item.get(
                "online"
            ) else 1,
            ipnum
        )

    final.sort(
        key=sort_ip
    )

    return final


# ============================================================
# ACTIVE DISCOVERY
# ============================================================

def discover_lans():

    state = load_state()

    scanned = []

    for interface, lan in state.get(
        "lans",
        {}
    ).items():

        address = lan.get(
            "address"
        )

        if not address:
            continue

        try:

            network = ipaddress.ip_interface(
                address
            ).network

        except Exception:
            continue

        #
        # Proteção contra redes gigantes.
        #

        if network.num_addresses > 1024:

            continue

        result = run([
            "nmap",
            "-sn",
            "-n",
            str(network)
        ], timeout=45)

        scanned.append({
            "interface": interface,
            "network": str(network),
            "success":
                result["success"]
        })

    return scanned


# ============================================================
# PORT ALIAS API
# ============================================================

@app.route(
    "/api/ports/aliases",
    methods=["GET"]
)
def api_port_aliases():

    return jsonify({
        "success": True,
        "aliases": get_aliases()
    })


@app.route(
    "/api/ports/alias",
    methods=["POST"]
)
def api_port_alias():

    data = request.get_json(
        silent=True
    ) or {}

    interface = data.get(
        "interface",
        ""
    )

    alias = str(
        data.get(
            "alias",
            ""
        )
    ).strip()

    if not valid_interface(
        interface
    ):

        return jsonify({
            "success": False,
            "message":
                "Interface inválida."
        }), 400

    if not interface_exists(
        interface
    ):

        return jsonify({
            "success": False,
            "message":
                "Interface não existe."
        }), 404

    aliases = get_aliases()

    if alias:

        aliases[
            interface
        ] = alias[:50]

    else:

        aliases.pop(
            interface,
            None
        )

    save_json_file(
        ALIASES_FILE,
        aliases
    )

    return jsonify({
        "success": True,
        "message":
            "Apelido salvo."
    })


# ============================================================
# DEVICES API
# ============================================================

@app.route(
    "/api/devices",
    methods=["GET"]
)
def api_devices():

    return jsonify({
        "success": True,
        "devices":
            build_device_list()
    })


@app.route(
    "/api/devices/discover",
    methods=["POST"]
)
def api_devices_discover():

    scans = discover_lans()

    return jsonify({
        "success": True,
        "scans": scans,
        "devices":
            build_device_list()
    })


@app.route(
    "/api/devices/name",
    methods=["POST"]
)
def api_device_name():

    data = request.get_json(
        silent=True
    ) or {}

    mac = normalize_mac(
        data.get(
            "mac",
            ""
        )
    )

    name = str(
        data.get(
            "name",
            ""
        )
    ).strip()

    if not re.fullmatch(
        r"([0-9a-f]{2}:){5}[0-9a-f]{2}",
        mac
    ):

        return jsonify({
            "success": False,
            "message":
                "MAC inválido."
        }), 400

    names = get_device_names()

    if name:

        names[
            mac
        ] = name[:80]

    else:

        names.pop(
            mac,
            None
        )

    save_json_file(
        DEVICE_NAMES_FILE,
        names
    )

    return jsonify({
        "success": True,
        "message":
            "Nome do dispositivo salvo."
    })




# NANOTECHROUTER_V040_BEGIN
# ============================================================
# NAT / PORT FORWARD / CONTROLE DE BANDA
# ============================================================

PORT_FORWARD_FILE = DATA + "/port_forwards.json"
BANDWIDTH_FILE = DATA + "/bandwidth_rules.json"

def nr_load(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def nr_save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=4)
    os.replace(tmp, path)

def nr_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except Exception:
        return False

def nr_port(value):
    try:
        value = int(value)
        return 1 <= value <= 65535
    except Exception:
        return False

def nr_rebuild_port_forwards():
    state = load_state()
    wan = state.get("wan")
    rules = nr_load(PORT_FORWARD_FILE, [])
    active = [x for x in rules if x.get("enabled", True)]

    run(["nft", "delete", "table", "ip", "nanotechrouter_pf"])

    # Limpa somente regras do NanotechRouter na DOCKER-USER.
    if run(["iptables", "-nL", "DOCKER-USER"])["success"]:
        while True:
            listing = run(["iptables", "-L", "DOCKER-USER", "-n", "--line-numbers"])
            number = None
            for line in listing.get("stdout", "").splitlines():
                if "nanotech-pf" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        number = parts[0]
                        break
            if not number:
                break
            run(["iptables", "-D", "DOCKER-USER", number])

    if not active:
        return {"success": True, "message": "Nenhum Port Forward ativo."}

    if not wan or not interface_exists(wan):
        return {"success": False, "message": "WAN não configurada."}

    r = run(["nft", "add", "table", "ip", "nanotechrouter_pf"])
    if not r["success"]:
        return r

    r = run([
        "nft", "add", "chain", "ip", "nanotechrouter_pf", "prerouting",
        "{", "type", "nat", "hook", "prerouting", "priority", "-100",
        ";", "policy", "accept", ";", "}"
    ])
    if not r["success"]:
        return r

    position = 1

    for rule in active:
        proto = rule["protocol"]
        external_port = str(rule["external_port"])
        internal_ip = rule["internal_ip"]
        internal_port = str(rule["internal_port"])

        r = run([
            "nft", "add", "rule", "ip", "nanotechrouter_pf", "prerouting",
            "iifname", wan, proto, "dport", external_port,
            "dnat", "to", internal_ip + ":" + internal_port
        ])
        if not r["success"]:
            return r

        r = run([
            "iptables", "-I", "DOCKER-USER", str(position),
            "-i", wan, "-p", proto, "-d", internal_ip,
            "--dport", internal_port,
            "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
            "-m", "comment", "--comment", "nanotech-pf",
            "-j", "ACCEPT"
        ])
        if not r["success"]:
            return r
        position += 1

    return {"success": True, "message": "Port Forward aplicado."}

def nr_apply_qos():
    state = load_state()
    rules = nr_load(BANDWIDTH_FILE, [])

    # Somente interfaces LAN são alteradas.
    for iface in state.get("lans", {}):
        if interface_exists(iface):
            run(["tc", "qdisc", "del", "dev", iface, "root"])
            run(["tc", "qdisc", "del", "dev", iface, "ingress"])

    grouped = {}
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        iface = rule.get("interface", "")
        if iface in state.get("lans", {}) and interface_exists(iface):
            grouped.setdefault(iface, []).append(rule)

    for iface, items in grouped.items():
        # DOWNLOAD: tráfego saindo pela LAN para o cliente.
        run(["tc", "qdisc", "add", "dev", iface, "root",
             "handle", "1:", "htb", "default", "999"])
        run(["tc", "class", "add", "dev", iface, "parent", "1:",
             "classid", "1:999", "htb", "rate", "1000mbit", "ceil", "1000mbit"])

        # UPLOAD: tráfego entrando da LAN.
        run(["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"])

        minor = 10
        for rule in items:
            ip = rule["ip"]
            down = int(rule.get("download_mbps", 0) or 0)
            up = int(rule.get("upload_mbps", 0) or 0)

            if down > 0:
                cid = "1:" + str(minor)
                run(["tc", "class", "add", "dev", iface, "parent", "1:",
                     "classid", cid, "htb", "rate", f"{down}mbit",
                     "ceil", f"{down}mbit", "burst", "64k"])
                run(["tc", "filter", "add", "dev", iface, "protocol", "ip",
                     "parent", "1:", "prio", "1", "u32",
                     "match", "ip", "dst", ip + "/32", "flowid", cid])
                minor += 1

            if up > 0:
                burst = max(64, up * 16)
                run(["tc", "filter", "add", "dev", iface, "parent", "ffff:",
                     "protocol", "ip", "prio", "1", "u32",
                     "match", "ip", "src", ip + "/32",
                     "police", "rate", f"{up}mbit", "burst", f"{burst}k",
                     "mtu", "64kb", "drop", "flowid", ":1"])

    return {"success": True, "message": "Controle de banda aplicado."}

@app.route("/api/nat/status")
def nr_nat_status():
    state = load_state()
    wan = state.get("wan")
    rows = []
    for iface, lan in state.get("lans", {}).items():
        try:
            network = str(ipaddress.ip_interface(lan["address"]).network)
        except Exception:
            network = ""
        rows.append({
            "interface": iface,
            "network": network,
            "wan": wan,
            "internet": bool(lan.get("internet"))
        })
    return jsonify({"success": True, "wan": wan, "nat": rows})

@app.route("/api/nat/forwards")
def nr_pf_list():
    return jsonify({"success": True, "rules": nr_load(PORT_FORWARD_FILE, [])})

@app.route("/api/nat/forward", methods=["POST"])
def nr_pf_save():
    data = request.get_json(silent=True) or {}
    proto = str(data.get("protocol", "tcp")).lower()
    internal_ip = str(data.get("internal_ip", "")).strip()

    if proto not in ("tcp", "udp"):
        return jsonify({"success": False, "message": "Protocolo inválido."}), 400
    if not nr_ipv4(internal_ip):
        return jsonify({"success": False, "message": "IP interno inválido."}), 400
    if not nr_port(data.get("external_port")) or not nr_port(data.get("internal_port")):
        return jsonify({"success": False, "message": "Porta inválida."}), 400

    rules = nr_load(PORT_FORWARD_FILE, [])
    rid = str(data.get("id", "")).strip()
    if not rid:
        import time
        rid = str(int(time.time() * 1000))

    new_rule = {
        "id": rid,
        "name": str(data.get("name", "")).strip()[:80] or "Redirecionamento",
        "protocol": proto,
        "external_port": int(data["external_port"]),
        "internal_ip": internal_ip,
        "internal_port": int(data["internal_port"]),
        "enabled": bool(data.get("enabled", True))
    }

    rules = [r for r in rules if str(r.get("id")) != rid]
    rules.append(new_rule)
    nr_save(PORT_FORWARD_FILE, rules)
    result = nr_rebuild_port_forwards()
    return jsonify({"success": result.get("success", False),
                    "message": result.get("message", "Salvo.")})

@app.route("/api/nat/forward/delete", methods=["POST"])
def nr_pf_delete():
    data = request.get_json(silent=True) or {}
    rid = str(data.get("id", ""))
    rules = [r for r in nr_load(PORT_FORWARD_FILE, [])
             if str(r.get("id")) != rid]
    nr_save(PORT_FORWARD_FILE, rules)
    nr_rebuild_port_forwards()
    return jsonify({"success": True, "message": "Redirecionamento removido."})

@app.route("/api/bandwidth")
def nr_bw_list():
    return jsonify({"success": True, "rules": nr_load(BANDWIDTH_FILE, [])})

@app.route("/api/bandwidth/rule", methods=["POST"])
def nr_bw_save():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    iface = str(data.get("interface", "")).strip()

    if not nr_ipv4(ip):
        return jsonify({"success": False, "message": "IP inválido."}), 400
    if not valid_interface(iface) or not interface_exists(iface):
        return jsonify({"success": False, "message": "Interface inválida."}), 400

    try:
        down = max(0, int(data.get("download_mbps", 0) or 0))
        up = max(0, int(data.get("upload_mbps", 0) or 0))
    except Exception:
        return jsonify({"success": False, "message": "Limites inválidos."}), 400

    rules = [r for r in nr_load(BANDWIDTH_FILE, []) if r.get("ip") != ip]
    rules.append({
        "ip": ip,
        "interface": iface,
        "download_mbps": down,
        "upload_mbps": up,
        "enabled": bool(data.get("enabled", True))
    })
    nr_save(BANDWIDTH_FILE, rules)
    result = nr_apply_qos()
    return jsonify({"success": result.get("success", False),
                    "message": result.get("message", "Salvo.")})

@app.route("/api/bandwidth/delete", methods=["POST"])
def nr_bw_delete():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", ""))
    rules = [r for r in nr_load(BANDWIDTH_FILE, []) if r.get("ip") != ip]
    nr_save(BANDWIDTH_FILE, rules)
    nr_apply_qos()
    return jsonify({"success": True, "message": "Limite removido."})

@app.route("/api/system/reapply", methods=["POST"])
def nr_reapply():
    if "rebuild_network_rules" in globals():
        network = rebuild_network_rules()
    else:
        network = rebuild_nat()
    pf = nr_rebuild_port_forwards()
    qos = nr_apply_qos()
    return jsonify({"success": True, "network": network,
                    "port_forward": pf, "qos": qos})

# NANOTECHROUTER_V040_END

# ============================================================
# API STATUS
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok"
    })


@app.route("/api/status")
def status():

    return jsonify({
        "success": True,
        "version": "0.3.0",
        "forwarding":
            open(
                "/proc/sys/net/ipv4/ip_forward"
            ).read().strip() == "1"
    })


# ============================================================
# API INTERFACES
# ============================================================

@app.route("/api/interfaces")
def interfaces():

    data = get_interfaces()

    return jsonify({
        "success": True,
        "count": len(data),
        "interfaces": data,
        "configuration": load_state()
    })


# ============================================================
# SET WAN
# ============================================================

@app.route(
    "/api/wan/set",
    methods=["POST"]
)
def set_wan():

    data = request.get_json(
        silent=True
    ) or {}

    interface = data.get(
        "interface"
    )

    if not valid_interface(interface):

        return jsonify({
            "success": False,
            "message": "Interface inválida."
        }), 400

    if not interface_exists(interface):

        return jsonify({
            "success": False,
            "message": "Interface não existe."
        }), 404

    state = load_state()

    if interface in state.get(
        "lans",
        {}
    ):

        return jsonify({
            "success": False,
            "message":
                "Essa interface está configurada como LAN. "
                "Remova a configuração LAN primeiro."
        }), 400

    state["wan"] = interface

    save_state(state)

    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])

    rebuild_network_rules()

    return jsonify({
        "success": True,
        "message":
            f"{interface} definida como WAN."
    })


# ============================================================
# CONFIGURE LAN
# ============================================================

@app.route(
    "/api/lan/set",
    methods=["POST"]
)
def set_lan():

    data = request.get_json(
        silent=True
    ) or {}

    interface = data.get(
        "interface"
    )

    address = data.get(
        "address"
    )

    dhcp = bool(
        data.get("dhcp")
    )

    dhcp_start = data.get(
        "dhcp_start",
        ""
    )

    dhcp_end = data.get(
        "dhcp_end",
        ""
    )

    dns = data.get(
        "dns",
        "1.1.1.1"
    )

    internet = bool(
        data.get("internet")
    )

    if not valid_interface(interface):

        return jsonify({
            "success": False,
            "message": "Interface inválida."
        }), 400

    if not interface_exists(interface):

        return jsonify({
            "success": False,
            "message": "Interface não existe."
        }), 404

    state = load_state()

    if state.get("wan") == interface:

        return jsonify({
            "success": False,
            "message":
                "Essa interface está configurada como WAN."
        }), 400

    try:

        lan_ip = ipaddress.ip_interface(
            address
        )

        if lan_ip.version != 4:
            raise ValueError()

    except Exception:

        return jsonify({
            "success": False,
            "message":
                "IP LAN inválido. Exemplo: 192.168.10.1/24"
        }), 400

    network = lan_ip.network

    if dhcp:

        try:

            start_ip = ipaddress.ip_address(
                dhcp_start
            )

            end_ip = ipaddress.ip_address(
                dhcp_end
            )

            dns_ip = ipaddress.ip_address(
                dns
            )

        except Exception:

            return jsonify({
                "success": False,
                "message":
                    "Faixa DHCP ou DNS inválido."
            }), 400

        if (
            start_ip not in network
            or end_ip not in network
        ):

            return jsonify({
                "success": False,
                "message":
                    "A faixa DHCP precisa pertencer à rede LAN."
            }), 400

        if int(start_ip) > int(end_ip):

            return jsonify({
                "success": False,
                "message":
                    "DHCP inicial é maior que o final."
            }), 400

    #
    # Removemos somente IPv4 da interface LAN.
    # Não fazemos isso na WAN.
    #

    run([
        "ip",
        "-4",
        "addr",
        "flush",
        "dev",
        interface
    ])

    result = run([
        "ip",
        "addr",
        "add",
        address,
        "dev",
        interface
    ])

    if not result["success"]:

        return jsonify({
            "success": False,
            "message": result["stderr"]
        }), 500

    run([
        "ip",
        "link",
        "set",
        interface,
        "up"
    ])

    state.setdefault(
        "lans",
        {}
    )

    state["lans"][interface] = {
        "address": address,
        "dhcp": dhcp,
        "dhcp_start": dhcp_start,
        "dhcp_end": dhcp_end,
        "dns": dns,
        "internet": internet
    }

    save_state(state)

    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])

    if dhcp:

        dhcp_result = start_dhcp(
            interface,
            str(lan_ip.ip),
            dhcp_start,
            dhcp_end,
            dns
        )

        if not dhcp_result["success"]:

            return jsonify({
                "success": False,
                "message":
                    "LAN configurada, mas DHCP falhou: "
                    + dhcp_result.get(
                        "message",
                        ""
                    )
            }), 500

    else:

        stop_dhcp(
            interface
        )

    network_result = rebuild_network_rules()

    return jsonify({
        "success": True,
        "message":
            f"LAN {interface} configurada.",
        "network": network_result
    })


# ============================================================
# REMOVE LAN
# ============================================================

@app.route(
    "/api/lan/delete",
    methods=["POST"]
)
def delete_lan():

    data = request.get_json(
        silent=True
    ) or {}

    interface = data.get(
        "interface"
    )

    state = load_state()

    if interface not in state.get(
        "lans",
        {}
    ):

        return jsonify({
            "success": False,
            "message":
                "Interface não está configurada como LAN."
        }), 404

    stop_dhcp(
        interface
    )

    run([
        "ip",
        "-4",
        "addr",
        "flush",
        "dev",
        interface
    ])

    del state["lans"][interface]

    save_state(state)

    rebuild_network_rules()

    return jsonify({
        "success": True,
        "message":
            f"Configuração LAN removida de {interface}."
    })


# ============================================================
# DHCP LEASES
# ============================================================

@app.route("/api/dhcp/leases")
def leases():

    state = load_state()

    result = []

    for interface in state.get(
        "lans",
        {}
    ):

        leasefile = (
            DATA
            + "/"
            + interface
            + ".leases"
        )

        if not os.path.exists(
            leasefile
        ):
            continue

        try:

            with open(leasefile) as f:

                for line in f:

                    parts = line.split()

                    if len(parts) >= 4:

                        result.append({
                            "interface": interface,
                            "expires": parts[0],
                            "mac": parts[1],
                            "ip": parts[2],
                            "hostname": parts[3]
                        })

        except Exception:
            pass

    return jsonify({
        "success": True,
        "leases": result
    })


# ============================================================
# STATE
# ============================================================

@app.route("/api/config")
def config():

    return jsonify({
        "success": True,
        "configuration": load_state()
    })


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5050
    )
