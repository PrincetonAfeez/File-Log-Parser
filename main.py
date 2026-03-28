# main.py
import sys
from parser import LogParser

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <logfile>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    parser = LogParser(file_path)
    parser.run()

if __name__ == "__main__":
    main()

#feat: implement basic CLI output summary