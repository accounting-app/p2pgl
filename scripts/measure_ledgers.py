#!/usr/bin/env python3
"""Measure a gl-node serving many ledgers (docs/build-log/003-multi-ledger-node).

Starts the built binary in a fresh directory with the config file's ledger and
N-1 ledger folders, waits until every ledger answers, and reports:

  boot     seconds from start until the last ledger answers its /health
  rss      resident memory once booted, and after one write per ledger
  files    open file descriptors once booted (lsof)
  write    seconds to write one entry into every ledger, one after another
  stop     seconds from SIGTERM to exit (every ledger compacts on the way out)

Usage:
  scripts/measure_ledgers.py [--ledgers N] [--p2p] [--entries N] [--binary PATH]
  scripts/measure_ledgers.py --mesh [--ledgers N]   two nodes, each ledger meshed with its pair

--p2p gives every ledger its own mesh and P2P endpoint (signing on, relays
off, a random UDP port each), as production ledgers have; without it every
ledger runs with P2P and signing off. HTTP and every mesh stay on loopback, but
each P2P endpoint is the production one: it binds all interfaces and asks the
network's gateway for a port mapping (UPnP / NAT-PMP / PCP), so --p2p and
--mesh send those probes to the LAN (an outbound firewall such as LuLu will
ask). The default binary is target/release/gl-node (build it with `cargo build
--release -p gl-node`). On a failure the work directory and its node.log are
kept, and their path printed.
"""

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ledger_settings(p2p, name):
    if not p2p:
        return {}
    return {
        "signing": {"enabled": True},
        "p2p": {
            "enabled": True,
            "relayMode": "disabled",
            "bootstrapEndpointIds": [],
            "meshId": f"measure-{name}-{secrets.token_hex(8)}",
            "swarmTopic": f"measure/{name}-{secrets.token_hex(8)}",
        },
    }


def post(port, path, key, query, client, timeout=30):
    # One simulated client per ledger (`X-Forwarded-For`, trusted from
    # loopback below): the GraphQL rate limit is per client, so one client
    # writing to 100 ledgers would measure the limit, not the node.
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps({"query": query}).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": key,
            "X-Forwarded-For": client,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def answers(port, path, key):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers={"X-Api-Key": key}
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status == 200
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return False


def rss_kib(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(out.stdout.strip() or 0)


def open_files(pid):
    out = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True)
    return max(0, len(out.stdout.splitlines()) - 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ledgers", type=int, default=100)
    parser.add_argument("--p2p", action="store_true")
    parser.add_argument("--binary", default="target/release/gl-node")
    parser.add_argument("--mesh", action="store_true",
                        help="two nodes, every ledger paired with its namesake on the other (see run_mesh)")
    parser.add_argument(
        "--entries",
        type=int,
        default=0,
        help="transactions typed into every ledger's .bean before boot (P2P off only)",
    )
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    if not os.path.exists(binary):
        sys.exit(f"{binary} not found; build it with: cargo build --release -p gl-node")
    if args.mesh:
        run_mesh(binary, args.ledgers)
        return

    work = tempfile.mkdtemp(prefix="gl-node-measure-")
    node = None
    succeeded = False
    try:
        port = free_port()
        key = secrets.token_hex(32)
        names = [f"l{index:03d}" for index in range(1, args.ledgers)]
        config = {
            "ledgerPath": "ledger.bean",
            "port": port,
            "auth": {"enabled": True, "apiKey": ""},
            "trustedProxies": ["127.0.0.1"],
            **ledger_settings(args.p2p, "default"),
        }
        with open(os.path.join(work, "gl-node.config.json"), "w") as file:
            json.dump(config, file)
        if args.entries and args.p2p:
            sys.exit("--entries is for P2P off: typed entries are signed at boot, which needs each ledger's key first")
        books = [os.path.join(work, "ledger.bean")]
        for name in names:
            folder = os.path.join(work, "data", "ledgers", name)
            os.makedirs(folder)
            with open(os.path.join(folder, "ledger.json"), "w") as file:
                json.dump(ledger_settings(args.p2p, name), file)
            books.append(os.path.join(folder, "ledger.bean"))
        if args.entries:
            lines = ["2025-01-01 open Assets:Bank USD", "2025-01-01 open Expenses:Supplies USD", ""]
            for index in range(args.entries):
                day = f"2025-{index % 12 + 1:02d}-{index % 28 + 1:02d}"
                lines += [
                    f'{day} * "Supplier {index % 97}" "Invoice {index}"',
                    f"  Expenses:Supplies  {index % 500 + 1}.{index % 100:02d} USD",
                    "  Assets:Bank",
                    "",
                ]
            text = "\n".join(lines)
            for book in books:
                with open(book, "w") as file:
                    file.write(text)
                os.chmod(book, 0o600)

        env = dict(os.environ, GL_NODE_CONFIG=os.path.join(work, "gl-node.config.json"), GL_NODE_API_KEY=key)
        env.pop("RUST_LOG", None)
        log = open(os.path.join(work, "node.log"), "w")
        started = time.monotonic()
        node = subprocess.Popen([binary], cwd=work, env=env, stdout=log, stderr=log)
        paths = ["/health"] + [f"/ledgers/{name}/health" for name in names]
        deadline = started + 600
        pending = list(paths)
        while pending:
            if node.poll() is not None:
                sys.exit(f"gl-node exited during boot; see {work}/node.log")
            if time.monotonic() > deadline:
                node.kill()
                sys.exit(f"not every ledger answered within 600 s; see {work}/node.log")
            pending = [path for path in pending if not answers(port, path, key)]
            if pending:
                time.sleep(0.2)
        boot = time.monotonic() - started
        rss_booted = rss_kib(node.pid)
        files = open_files(node.pid)

        write_started = time.monotonic()
        for index, path in enumerate(["/graphql"] + [f"/ledgers/{name}/graphql" for name in names]):
            client = f"10.0.{index // 250}.{index % 250 + 1}"
            answer = post(port, path, key, 'mutation { openAccount(name: "Assets:Cash", date: "2026-01-01") }', client)
            if answer.get("errors"):
                sys.exit(f"{path}: {answer['errors']}")
        write = time.monotonic() - write_started
        rss_written = rss_kib(node.pid)

        stop_started = time.monotonic()
        node.send_signal(signal.SIGTERM)
        code = node.wait(timeout=300)
        stop = time.monotonic() - stop_started

        succeeded = code == 0
        print(json.dumps({
            "ledgers": args.ledgers,
            "entries_per_ledger": args.entries,
            "p2p": args.p2p,
            "boot_seconds": round(boot, 2),
            "rss_mib_booted": round(rss_booted / 1024, 1),
            "rss_mib_after_writes": round(rss_written / 1024, 1),
            "open_files": files,
            "write_seconds": round(write, 2),
            "stop_seconds": round(stop, 2),
            "exit_code": code,
        }))
        if code != 0:
            sys.exit(f"gl-node exited {code}; see {work}/node.log")
    finally:
        if node is not None and node.poll() is None:
            node.kill()
            node.wait()
        if succeeded:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"kept {work} for its node.log", file=sys.stderr)


def free_udp_ports(count):
    """`count` distinct free UDP ports: each socket stays bound until all are
    chosen, so no port is handed out twice (two ledgers on one port are
    refused by the node, as they should be)."""
    sockets = []
    try:
        ports = []
        while len(ports) < count:
            # Below the ephemeral range (49152+ on macOS, 32768+ on Linux), so
            # no socket the running nodes open on their own lands on a port
            # chosen here before its ledger binds it; free on IPv4 and IPv6
            # alike, as the endpoint binds both families.
            port = secrets.randbelow(10000) + 20000
            if port in ports:
                continue
            v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                v4.bind(("0.0.0.0", port))
                v6.bind(("::", port))
            except OSError:
                v4.close()
                v6.close()
                continue
            sockets += [v4, v6]
            ports.append(port)
        return ports
    finally:
        for sock in sockets:
            sock.close()


def run_mesh(binary, count):
    """Two nodes, `count` ledgers each, every ledger paired with its namesake
    on the other node in a mesh of its own (direct loopback addresses, no
    relay). One entry per ledger is written on node A; reports how long until
    node B holds every one, and checks no entry crossed into another ledger."""
    work = tempfile.mkdtemp(prefix="gl-node-mesh-")
    nodes = []
    succeeded = False
    try:
        names = ["default"] + [f"l{index:03d}" for index in range(1, count)]
        pairs = {
            name: {
                "meshId": f"mesh-{name}-{secrets.token_hex(8)}",
                "swarmTopic": f"measure/{name}-{secrets.token_hex(8)}",
            }
            for name in names
        }
        ports = iter(free_udp_ports(2 * len(names)))
        for side in ("a", "b"):
            home = os.path.join(work, side)
            os.makedirs(home)
            nodes.append({
                "home": home,
                "port": free_port(),
                "key": secrets.token_hex(32),
                "udp": {name: next(ports) for name in names},
                "ids": {},
            })

        def p2p_section(node, name, peer=None):
            section = {
                "enabled": True,
                "relayMode": "disabled",
                "meshId": pairs[name]["meshId"],
                "swarmTopic": pairs[name]["swarmTopic"],
                "listenPort": node["udp"][name],
                "bootstrapEndpointIds": [],
            }
            if peer is not None:
                peer_id = peer["ids"][name]
                section["bootstrapEndpointIds"] = [peer_id]
                section["peerAddresses"] = {peer_id: [f"127.0.0.1:{peer['udp'][name]}"]}
            return section

        def write_configs(node, peer=None):
            config = {
                "ledgerPath": "ledger.bean",
                "port": node["port"],
                "auth": {"enabled": True, "apiKey": ""},
                "trustedProxies": ["127.0.0.1"],
                "signing": {"enabled": True},
                "p2p": p2p_section(node, "default", peer),
            }
            with open(os.path.join(node["home"], "gl-node.config.json"), "w") as file:
                json.dump(config, file)
            for name in names[1:]:
                folder = os.path.join(node["home"], "data", "ledgers", name)
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, "ledger.json"), "w") as file:
                    json.dump({"signing": {"enabled": True}, "p2p": p2p_section(node, name, peer)}, file)

        def env_for(node):
            env = dict(os.environ, GL_NODE_CONFIG=os.path.join(node["home"], "gl-node.config.json"),
                       GL_NODE_API_KEY=node["key"])
            env.pop("RUST_LOG", None)
            return env

        for node in nodes:
            write_configs(node)
            for name in names:
                command = [binary, "--node-id"] + ([] if name == "default" else ["--ledger", name])
                out = subprocess.run(command, cwd=node["home"], env=env_for(node), capture_output=True, text=True)
                if out.returncode != 0:
                    sys.exit(f"--node-id {name}: {out.stderr}")
                node["ids"][name] = out.stdout.strip()
        write_configs(nodes[0], nodes[1])
        write_configs(nodes[1], nodes[0])

        def path_of(name, what):
            return f"/{what}" if name == "default" else f"/ledgers/{name}/{what}"

        clients = iter(range(1, 60000))

        def client():
            index = next(clients)
            return f"10.{index // 62500}.{index // 250 % 250}.{index % 250 + 1}"

        for node in nodes:
            node["log"] = open(os.path.join(node["home"], "node.log"), "w")
            node["process"] = subprocess.Popen([binary], cwd=node["home"], env=env_for(node),
                                               stdout=node["log"], stderr=node["log"])
        for node in nodes:
            deadline = time.monotonic() + 120
            pending = [path_of(name, "health") for name in names]
            while pending:
                if node["process"].poll() is not None or time.monotonic() > deadline:
                    sys.exit(f"node {node['home']} did not boot; see its node.log")
                pending = [path for path in pending if not answers(node["port"], path, node["key"])]
                time.sleep(0.2)

        a, b = nodes
        for name in names:
            for account in ("Assets:Cash", "Income:Sales"):
                post(a["port"], path_of(name, "graphql"), a["key"],
                     f'mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}', client())
            answer = post(a["port"], path_of(name, "graphql"), a["key"],
                          'mutation { appendTransaction(input: { date: "2026-01-02", narration: "entry in '
                          + name + '", postings: [{ account: "Assets:Cash", amount: { number: "1", currency: '
                          '"USD" } }, { account: "Income:Sales" }] }) { txid } }', client())
            if answer.get("errors"):
                sys.exit(f"{name}: {answer['errors']}")
        written = time.monotonic()
        seen = {}
        deadline = written + 120
        while len(seen) < len(names) and time.monotonic() < deadline:
            for name in names:
                if name in seen:
                    continue
                answer = post(b["port"], path_of(name, "graphql"), b["key"], "{ journal { narration } }", client())
                narrations = [row["narration"] for row in (answer.get("data") or {}).get("journal") or []]
                if narrations:
                    seen[name] = (time.monotonic() - written, narrations)
            time.sleep(0.25)
        crossed = {name: rows for name, (_, rows) in seen.items() if rows != [f"entry in {name}"]}
        for node in nodes:
            node["process"].send_signal(signal.SIGTERM)
            node["process"].wait(timeout=120)
        print(json.dumps({
            "mesh": "two nodes",
            "ledgers_per_node": count,
            "replicated": len(seen),
            "slowest_seconds": round(max((delay for delay, _ in seen.values()), default=0), 2),
            "crossed_into_another_ledger": crossed,
        }))
        if len(seen) < len(names) or crossed:
            sys.exit(1)
        succeeded = True
    finally:
        for node in nodes:
            process = node.get("process")
            if process and process.poll() is None:
                process.kill()
                process.wait()
        if succeeded:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"kept {work} for the nodes' node.log", file=sys.stderr)


if __name__ == "__main__":
    main()
