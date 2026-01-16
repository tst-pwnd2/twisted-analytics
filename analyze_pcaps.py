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

    defaults = {"direction": direction, "eventType": eventType, "packets": []}

    for m in match:
        if isinstance(m.value, list):
            events.extend([add_defaults(e, defaults) for e in m.value])
        else:
            events.append(add_defaults(m.value, defaults))

    return events


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
            packet.haslayer("IP")
            and packet.haslayer("DNS")
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
                                "response": packet.qr == 1,
                            }
                        )
                        # last_event_idx = idx
                        break
                else:
                    click.echo(
                        f"Unable to find event for packet @ {packet.time}", err=True
                    )


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


if __name__ == "__main__":
    analyze()
