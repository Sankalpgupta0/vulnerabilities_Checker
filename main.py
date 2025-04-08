import argparse
from wagsecure.scanner import scan_site

def main():
    parser = argparse.ArgumentParser(description="WagSecure - Wagtail Security Scanner")
    parser.add_argument('--url', required=True, help='Target website URL (e.g. https://example.com)')
    args = parser.parse_args()

    scan_site(args.url)

if __name__ == "__main__":
    main()
