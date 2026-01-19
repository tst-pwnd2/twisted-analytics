import json
from collections import defaultdict

import click


def calculate_rolling_query_rate(
    prev_periods: list[float],
    prev_query: dict | None,
    queries: list[dict],
    rolling_count: int,
) -> tuple[list[float], dict, list[float], list[float], float]:
    if len(queries) == 0:
        return prev_periods, prev_query, [], 0.0

    periods = list(prev_periods)
    last_query = prev_query
    rolling_avgs = []

    processed = []
    event_periods = []

    first_query = True
    for query in queries:
        if last_query is None:
            # Cannot calculate a rate for the very first query
            last_query = query
            processed.append(
                dict(
                    packet=dict(
                        time=query["time"],
                        sizes=query["sizes"],
                        domain=query["domain"],
                    )
                )
            )
            continue

        this_period = query["time"] - last_query["time"]
        last_query = query

        if not first_query:
            event_periods.append(this_period)
        first_query = False

        # Keep count-1 of the periods for rolling avg calculation
        if len(periods) >= rolling_count:
            periods = periods[-(rolling_count - 1) :]
        periods += [this_period]

        rolling_avg = sum(periods) / len(periods)
        rolling_avgs.append(rolling_avg)

        processed.append(
            dict(
                packet=dict(
                    time=query["time"],
                    sizes=query["sizes"],
                    domain=query["domain"],
                ),
                period=this_period,
                rolling=rolling_avg,
            )
        )

    event_avg = (
        sum(event_periods) / len(event_periods) if len(event_periods) > 0 else 0.0
    )

    return periods, last_query, processed, event_avg


@click.group()
def analyze():
    pass


@analyze.command()
@click.argument("packetsfile")
@click.option(
    "--out",
    default="iodine_event_poll_rates.json",
    help="JSON file to which to write results",
)
@click.option(
    "--rolling-count",
    default=10,
    help="Number of queries to use for the rolling average",
    type=int,
)
def poll_rate(packetsfile: str, out: str, rolling_count: int):
    """
    Calculate the iodine poll-rate during events defined in the PACKETSFILE
    """
    with open(packetsfile, "r", encoding="UTF-8") as infile:
        events: list[dict] = json.load(infile)

    prev_rates = []
    prev_query = None
    event_results = []
    avgs_by_event_type = defaultdict(list)
    first_idle = True
    for event in events:
        queries = [p for p in event["packets"] if not p["response"]]
        prev_rates, prev_query, processed_queries, event_avg_rate = (
            calculate_rolling_query_rate(prev_rates, prev_query, queries, rolling_count)
        )
        event_results.append(
            dict(
                start_ts=event["start_ts"],
                stop_ts=event["stop_ts"],
                duration=event["duration"],
                eventType=event["eventType"],
                direction=event.get("direction"),
                num_queries=len(queries),
                queries=processed_queries,
                event_avg_rate=event_avg_rate,
            )
        )
        # Don't add the first idle event to the type averages because it has initialization in it
        if event["eventType"] == "idle" and first_idle:
            first_idle = False
            continue

        if event_avg_rate > 0:
            avgs_by_event_type[
                f'{event["eventType"]}-{event.get("direction", "na")}'
            ].append(event_avg_rate)

    results = dict(
        events=event_results,
        by_event_type={k: sum(v) / len(v) for k, v in avgs_by_event_type.items()},
    )

    with open(out, "w", encoding="UTF-8") as outfile:
        json.dump(results, outfile, indent=2, default=str)


if __name__ == "__main__":
    analyze()
