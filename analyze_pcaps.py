import json
import sys
from pprint import pprint
from typing import TYPE_CHECKING

import click
import jsonpath_ng
from scapy.all import rdpcap
from scapy.layers import dns

if TYPE_CHECKING:
    from scapy.packet import Packet


@click.group()
def analyze():
    pass


def add_defaults(data: dict, defaults: dict) -> dict:
    for key, default in defaults.items():
        if key not in data:
            data[key] = default
    return data


def parse_events(
    eventsdata: dict, jsonpath: str, eventType: str, direction: str | None = None
):
    events = []

    pathexpr = jsonpath_ng.parse(jsonpath)
    match = pathexpr.find(eventsdata)

    if not match:
        click.echo(f"No events found at path '{jsonpath}'", err=True)
        return events

    for m in match:
        if isinstance(m.value, list):
            events.extend(
                [
                    add_defaults(
                        e, dict(direction=direction, eventType=eventType, packets=[])
                    )
                    for e in m.value
                ]
            )
        else:
            events.append(
                add_defaults(
                    m.value, dict(direction=direction, eventType=eventType, packets=[])
                )
            )

    return events


def create_continuous_event_timeline(
    sparse_events: list[dict],
    start_key: str = "start_ts",
    stop_key: str = "stop_ts",
) -> list[dict]:
    if not sparse_events:
        click.echo("No events found", err=True)
        return sparse_events

    sparse_events.sort(key=lambda e: e[start_key])

    continuous_events = [
        {
            start_key: 0,
            stop_key: sparse_events[0][start_key],
            "duration": sparse_events[0][start_key],
            "eventType": "idle",
            "packets": [],
        }
    ]

    prev_event = continuous_events[0]
    for event in sparse_events:
        if event[start_key] > prev_event[stop_key]:
            continuous_events.append(
                {
                    start_key: prev_event[stop_key],
                    stop_key: event[start_key],
                    "duration": event[start_key] - prev_event[stop_key],
                    "eventType": "idle",
                    "packets": [],
                }
            )
        continuous_events.append(event)
        prev_event = event

    continuous_events.append(
        {
            start_key: prev_event[stop_key],
            stop_key: prev_event[stop_key] + 3600.0,  # 1 hour
            "duration": 3600.0,
            "eventType": "idle",
            "packets": [],
        }
    )

    return continuous_events


def build_event_timeline(
    eventsdata: dict,
    jsonpath: str | list[str],
    eventType: str,
    start_key: str = "start_ts",
    stop_key: str = "stop_ts",
    direction: str | None = None,
):
    sparse_events = []
    for path in jsonpath if isinstance(jsonpath, list) else [jsonpath]:
        sparse_events.extend(parse_events(eventsdata, path, eventType, direction))
    return create_continuous_event_timeline(
        sparse_events, start_key=start_key, stop_key=stop_key
    )


def assign_dns_packets_to_events(
    events: list[dict],
    packets: list["Packet"],
    domain: str = "t1.pwnd.com",
    start_key: str = "start_ts",
    stop_key: str = "stop_ts",
):
    last_event_idx = 0
    for packet in packets:
        if (
            packet.haslayer("DNS")
            and packet["DNS"].qd
            and isinstance(packet["DNS"].qd[0], dns.DNSQR)
        ):
            qname = str(packet["DNS"].qd.qname)
            if domain in qname:
                for idx in range(last_event_idx, len(events)):
                    event = events[idx]
                    if (
                        event[start_key] <= packet.time
                        and packet.time < event[stop_key]
                    ):
                        qtype = packet["DNS"].qd.qtype
                        event["packets"].append(
                            {
                                "description": str(packet.getlayer(0)),
                                "time": float(packet.time),
                                "sizes": {
                                    l.__name__: len(packet[l]) for l in packet.layers()
                                },
                                "srcIp": packet["IP"].src,
                                "destIp": packet["IP"].dst,
                                "domain": qname,
                                "record": dns.dnsqtypes.get(qtype, str(qtype)),
                                "response": packet["DNS"].qr == 1,
                            }
                        )
                        # last_event_idx = idx
                        break
                else:
                    click.echo(
                        f"Unable to find event for packet {packet.getlayer(0)} @ {packet.time}",
                        err=True,
                    )


HTTP_PORTS = (80, 443)
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def assign_http_packets_to_events(
    events: list[dict],
    packets: list["Packet"],
    start_key: str = "start_ts",
    stop_key: str = "stop_ts",
):
    last_event_idx = 0
    for packet in packets:
        if packet.haslayer("TCP") and (
            packet["TCP"].dport in HTTP_PORTS or packet["TCP"].sport in HTTP_PORTS
        ):
            packet_data = {
                "description": str(packet.getlayer(0)),
                "time": float(packet.time),
                "sizes": {l.__name__: len(packet[l]) for l in packet.layers()},
                "srcIp": packet["IP"].src,
                "srcPort": packet["TCP"].sport,
                "destIp": packet["IP"].dst,
                "destPort": packet["TCP"].dport,
                "direction": (
                    "client-to-server"
                    if packet["TCP"].dport in HTTP_PORTS
                    else "server-to-client"
                ),
                "flags": [TCP_FLAGS[f] for f in str(packet["TCP"].flags)],
            }

            last_event = None
            for idx in range(last_event_idx, len(events)):
                event = events[idx]
                if event[start_key] <= packet.time and packet.time < event[stop_key]:
                    event["packets"].append(packet_data)
                    # last_event_idx = idx
                    break
                if (
                    last_event
                    and last_event[stop_key] < packet.time
                    and packet.time < event[start_key]
                ):
                    last_event["packets"].append(packet_data)
                    break
                last_event = event
            else:
                if last_event and last_event[stop_key] < packet.time:
                    last_event["packets"].append(packet_data)
                else:
                    click.echo(
                        f"Unable to find event for packet {packet.getlayer(0)} @ {packet.time}",
                        err=True,
                    )


def sort_packets_in_events(events: list[dict]):
    for event in events:
        event["packets"].sort(key=lambda p: p["time"])


def assign_packets_to_post_operations(events):
    for event in events:
        if (
            event["eventType"] != "raceboat"
            or event["direction"] != "upstream"
            or not event.get("operations")
        ):
            continue

        operations = [dict(**o, packets=[]) for o in event["operations"]]

        current_dns_op_idx = 0
        current_http_op_idx = -1

        syns = [
            p
            for p in event["packets"]
            if "flags" in p
            and p["direction"] == "client-to-server"
            and p["flags"] == ["SYN"]
        ]
        if len(operations) != len(syns):
            click.echo(
                f"There are {len(operations)} operations in this event but {len(syns)} client-initiated SYNs",
                err=True,
            )

        for packet in event["packets"]:
            if "domain" in packet:
                if current_dns_op_idx >= len(operations):
                    click.echo(
                        "Cannot assign DNS packet to operation, saw too many resolutions",
                        err=True,
                    )
                    continue

                operations[current_dns_op_idx]["packets"].append(packet)

            elif "flags" in packet:
                # Go to the next operation when we see the first SYN from client to server
                if packet.get("direction") == "client-to-server" and packet.get(
                    "flags"
                ) == ["SYN"]:
                    current_http_op_idx += 1
                    current_dns_op_idx += 1

                if current_http_op_idx < 0:
                    click.echo(
                        "Cannot assign HTTP packet to operation, didn't see initial SYN",
                        err=True,
                    )
                    continue

                if current_http_op_idx >= len(operations):
                    click.echo(
                        "Cannot assign HTTP packet to operation, saw too many initial SYNs",
                        err=True,
                    )
                    continue

                operations[current_http_op_idx]["packets"].append(packet)

        for idx, operation in enumerate(operations):
            if len(operation["packets"]) == 0:
                click.echo(f"Did not assign any packets to operation #{idx}", err=True)

        event["operations"] = operations


@analyze.command()
@click.argument("pcapfile")
@click.argument("eventsfile")
@click.option(
    "--out",
    default="iodine_events_and_packets.json",
    help="JSON file to which to write results",
)
def iodine(pcapfile: str, eventsfile: str, out: str):
    """
    Parse PCAPFILE to attach packets to network events from EVENTSFILE.
    """
    with open(eventsfile, "r", encoding="UTF-8") as infile:
        eventsdata: dict = json.load(infile)

    events = build_event_timeline(
        eventsdata, ["iodineUpstream.*.data", "iodineDownstream.*.data"], "iodine"
    )

    packets = rdpcap(pcapfile)
    assign_dns_packets_to_events(events, packets)

    with open(out, "w", encoding="UTF-8") as outfile:
        json.dump(events, outfile, indent=2, default=str)


@analyze.command()
@click.argument("pcapfile")
@click.argument("eventsfile")
@click.option(
    "--out",
    default="raceboat_events_and_packets.json",
    help="JSON file to which to write results",
)
def raceboat(pcapfile: str, eventsfile: str, out: str):
    """
    Parse PCAPFILE to attach packets to network events from EVENTSFILE.
    """
    with open(eventsfile, "r", encoding="UTF-8") as infile:
        eventsdata: dict = json.load(infile)

    events = []
    events.extend(
        parse_events(
            eventsdata, "detailedRaceboatPosting.*.data", "raceboat", "upstream"
        )
    )
    events.extend(
        parse_events(eventsdata, "raceboatFetching.*.data", "raceboat", "downstream")
    )
    events.sort(key=lambda e: e["start_ts"])

    packets = rdpcap(pcapfile)
    assign_dns_packets_to_events(events, packets, domain="mastodon.pwnd.com")
    assign_http_packets_to_events(events, packets)
    sort_packets_in_events(events)
    assign_packets_to_post_operations(events)

    with open(out, "w", encoding="UTF-8") as outfile:
        json.dump(events, outfile, indent=2, default=str)


if __name__ == "__main__":
    analyze()
