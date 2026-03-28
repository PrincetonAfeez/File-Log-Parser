# main.py
"""Command-line entrypoint: run analysis on a log file and optionally export results."""

import asyncio

import click

from parser import LogParser


@click.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--threshold", default=50, help="404 threshold.")
@click.option("--export", type=click.Choice(["json", "csv"]), help="Export format.")
@click.option("--output", default="report", help="Output filename without extension.")
def main(logfile, threshold, export, output):
    """Analyze ``logfile``, print summaries, and optionally write JSON or CSV."""
    parser = LogParser(logfile)
    
    # Standard way to run async code from a synchronous CLI
    asyncio.run(parser.run(threshold=threshold))
    
    if export:
        parser.export_data(export, output)

if __name__ == "__main__":
    main()