import click


@click.group()
def cp2():
    pass


@cp2.group()
def parse():
    pass


@parse.command()
@click.argument("basepath")
@click.option(
    "--out",
    default="events.json",
    help="JSON file to which to write output",
)
def events(basepath: str, out: str) -> None:
    from twisted_analytics import log_parser

    config = log_parser.LoggedEventConfig(
        events=dict(
            iodineUpstream=log_parser.LoggedEventFromMultiline(
                start_search_text=r"Sending .*via Iodine",
                start_file_pattern="app_client.log",
                stop_search_text="Received Iodine Control Message Type:",
                stop_file_pattern="app_server.log",
            ),
            iodineDownstream=log_parser.LoggedEventFromMultiline(
                start_search_text=r"Sending .*via Iodine",
                start_file_pattern="app_server.log",
                stop_search_text="Recieved Iodine Message for File",
                stop_file_pattern="app_client.log",
            ),
            raceboatPosting=log_parser.LoggedEventFromMultiline(
                start_search_text="Raceboat::TransportComponentWrapper::doAction: called with handlesJson",
                start_file_pattern="raceboat_client.log",
                stop_search_text="PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json",
                stop_file_pattern="raceboat_client.log",
            ),
            raceboatFetching=log_parser.LoggedEventFromMultiline(
                start_search_text="PluginMastodon::doAction: Fetching from single link",
                start_file_pattern="raceboat_server.log",
                stop_search_text=r"Link::fetch: Fetched [0-9]+ items",
                stop_file_pattern="raceboat_server.log",
            ),
            tgenDns=log_parser.LoggedEventFromJson(
                search_text=r"STATS=.*type\": \"(?!wait)",
                file_pattern="tgen_logs/dns_client_group_*/logs/user*.log",
                json_pattern=r"STATS=(.*)$",
                stop_time_field="timestamp",
                duration_field="elapsed_time",
            ),
            tgenPosting=log_parser.LoggedEventFromJson(
                search_text=r"STATS.*num_to_post",
                file_pattern="tgen_logs/mastodon*client_group_*/logs/user*.log",
                json_pattern=r"STATS=(.*)$",
                stop_time_field="timestamp",
                duration_field="elapsed_time",
            ),
            tgenFetching=log_parser.LoggedEventFromJson(
                search_text=r"STATS.*monitor_download",
                file_pattern="tgen_logs/mastodon*client_group_*/logs/user*.log",
                json_pattern=r"STATS=(.*)$",
                stop_time_field="timestamp",
                duration_field="elapsed_time",
            ),
        )
    )

    results = log_parser.parse_events(basepath, config)

    with open(out, "w", encoding="UTF-8") as outfile:
        outfile.write(results.model_dump_json(indent=2))


if __name__ == "__main__":
    cp2()
