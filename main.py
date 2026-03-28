# main.py
import click # For CLI argument handling
from parser import LogParser

@click.command()
@click.argument('logfile', type=click.Path(exists=True))
@click.option('--threshold', default=50, help='404 error count to trigger a security alert.')
def main(logfile, threshold):
    """Enterprise Log File Parser - Data Integrity & Security Guard."""
    parser = LogParser(logfile)
    parser.run(threshold=threshold)

if __name__ == "__main__":
    main()

#feat: implement basic CLI output summary