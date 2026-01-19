# Analytics Tooling

## Required dependencies

The required dependencies are identified in the `pyproject.toml` file and may be
installed via `pip`, `uv`, `poetry`, etc.

## Generating event data

Parses monitor node and raceboat client and server logs to extract timings of actions and produce distributions.

```
python monitor_parse.py <tgen_log_file> <raceboat_post_log_file> <raceboat_fetch_log_file> <results_file>"
```

Produces `analysis.results.json` as output.

## Associating PCAP packets with events

### Iodine traffic

```sh
python analyze_pcaps.py iodine <pcapfile> <eventsfile>
```

Using the PCAP file from the node running the iodine client and the
`analysis_results.json` file produced by [Generating event data](#generating-event-data).

For example,

```sh
python analyze_pcaps.py iodine \
    spot_check_1/spot_check_1_2026_01_08_20_35_02_877688/pcaps/pcaps/user_alice_eth0_2026_01_08_20_30_20.pcap \
    analysis_results.json
```

Produces `iodine_events_and_packets.json` as output.

### Raceboat posting traffic

```sh
python analyze_pcaps.py raceboat-post <pcapfile> <eventsfile>

Using the PCAP file from the node performing post actions via raceboat and the
`analysis_results.json` file produced by [Generating event data](#generating-event-data).

For example,

```sh
python analyze_pcaps.py raceboat-post \
    spot_check_1/spot_check_1_2026_01_08_20_35_02_877688/pcaps/pcaps/user_alice_eth0_2026_01_08_20_30_20.pcap \
    analysis_results.json
```

Produces `raceboat_post_events_and_packets.json` as output.

### Raceboat fetching traffic

```sh
python analyze_pcaps.py raceboat-fetch <pcapfile> <eventsfile>
```

Using the PCAP file from the node performing fetch actions via raceboat and the
`analysis_results.json` file produced by [Generating event data](#generating-event-data).

For example,

```sh
python analyze_pcaps.py raceboat-fetch \
    spot_check_1/spot_check_1_2026_01_08_20_35_02_877688/pcaps/pcaps/user_bob_eth0_2026_01_08_20_30_20.pcap \
    analysis_results.json
```

Produces `raceboat_fetch_events_and_packets.json` as output.
