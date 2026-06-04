import argparse
import sys

from ssl_sentinel.__about__ import __version__
from ssl_sentinel.exceptions import SSLSentinelError
from ssl_sentinel.models import CheckResult
from ssl_sentinel.network import fetch_certificate_status
from ssl_sentinel.views import FORMATTERS


def check_hostname(hostname: str, threshold: int) -> CheckResult:
    """
    Check the SSL certificate status for a given hostname.

    Args:
        hostname (str): The domain name to check.
        threshold (int): The number of days remaining to consider a certificate expiring soon.

    Returns:
        CheckResult: The structured outcome of the certificate check (success or failure).
    """
    try:
        certificate = fetch_certificate_status(hostname=hostname, threshold=threshold)
        return CheckResult(
            hostname=hostname,
            success=True,
            status=certificate.status_label,
            days_left=certificate.days_left,
            expiry_date=certificate.expiry_date,
        )

    except SSLSentinelError as e:
        return CheckResult(
            hostname=hostname, success=False, status="ERROR", error=str(e)
        )


def main():
    """
    Main entry point for the ssl-sentinel CLI. Parses arguments and initiates processing.
    """
    parser = argparse.ArgumentParser(
        description="Check the SSL certificate for a domain name.", prog="ssl-sentinel"
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--expiring-soon",
        dest="expiring_soon",
        action="store_true",
        help="Show only certificates that are expiring within 30 days or are already expired",
    )

    parser.add_argument(
        "-t",
        "--threshold",
        dest="threshold",
        type=int,
        default=30,
        help='Set the number of days to consider a certificate as "expiring soon" (default: 30 days)',
    )

    parser.add_argument("--format", choices=list(FORMATTERS.keys()), default="text")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-H",
        "--hostname",
        dest="hostname",
        type=str,
        help="Domain name to check the SSL certificate for",
    )
    group.add_argument(
        "-f",
        "--file",
        dest="file",
        type=str,
        help="File containing a list of domain names to check",
    )

    args = parser.parse_args()

    results = []

    if args.hostname:
        results.append(check_hostname(args.hostname, args.threshold))
    elif args.file:
        try:
            with open(args.file, "r") as f:
                for line in f:
                    hostname = line.strip()

                    if not hostname or hostname.startswith("#"):
                        # Skip empty lines or commented lines
                        continue

                    results.append(
                        check_hostname(hostname=hostname, threshold=args.threshold)
                    )

        except FileNotFoundError:
            print(f"Error: The file '{args.file}' was not found.", file=sys.stderr)
            sys.exit(1)
    else:
        while True:
            hostname = input(
                "Enter the domain name to check the SSL certificate for: "
            ).strip()
            if hostname or hostname != "":
                break
            else:
                print("\n[ERROR]: The hostname can not be empty or a white space.")

        results.append(check_hostname(hostname, args.threshold))

    if args.expiring_soon:
        results = [res for res in results if res.status != "OK"]

    formater = FORMATTERS[args.format]

    output = formater(results)

    if output:
        print(output)


if __name__ == "__main__":
    main()
