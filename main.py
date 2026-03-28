# main.py
import click # For CLI argument handling
from parser import LogParser

@click.command()
@click.argument('logfile', type=click.Path(exists=True))
@click.option('--threshold', default=50, help='404 threshold.')
@click.option('--export', type=click.Choice(['json', 'csv']), help='Export format.')
def main(logfile, threshold, export):
    """Enterprise Log File Parser."""
    parser = LogParser(logfile)
    parser.run(threshold=threshold)
    
    if export:
        parser.export_data(export)

if __name__ == "__main__":
    main()

#feat: implement basic CLI output summary