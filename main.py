# main.py
"""Command-line entrypoint: run analysis on a log file and optionally export results."""

# Import the asyncio library to manage the asynchronous event loop for the parser.
import asyncio

# Import the click library to create a robust and user-friendly Command Line Interface (CLI).
import click

# Import the LogParser class which contains the core orchestration logic for the app.
from parser import LogParser


# Define the primary CLI command using the click decorator.
@click.command()
# Define a required argument: the path to the log file, ensuring the file actually exists on disk.
@click.argument("logfile", type=click.Path(exists=True))
# Define an optional parameter for the 404 error limit before an IP is flagged (defaults to 50).
@click.option("--threshold", default=50, help="404 threshold.")
# Define an optional parameter to export the results, restricted to 'json' or 'csv' formats.
@click.option("--export", type=click.Choice(["json", "csv"]), help="Export format.")
# Define an optional parameter for the custom output filename, defaulting to 'report'.
@click.option("--output", default="report", help="Output filename without extension.")
def main(logfile, threshold, export, output):
    """Analyze ``logfile``, print summaries, and optionally write JSON or CSV."""
    
    # Initialize the LogParser instance with the provided log file path.
    parser = LogParser(logfile)
    
    # Execute the asynchronous 'run' method of the parser within the standard synchronous CLI flow.
    # This initializes the event loop, streams the file, and prints the terminal summary.
    asyncio.run(parser.run(threshold=threshold))
    
    # Check if the user requested an export (JSON or CSV) via the CLI flags.
    if export:
        # Trigger the data export logic to save the analysis results to a file.
        parser.export_data(export, output)

# Standard Python idiom to ensure the main function runs only when the script is executed directly.
if __name__ == "__main__":
    # Call the click-decorated main function to start the application.
    main()