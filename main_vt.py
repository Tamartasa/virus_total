import argparse

from vt_class import VtManager


def get_args():
    parser = argparse.ArgumentParser(
        prog="Virus Total Tool",
        description="Enter url(s) separated by comma to check the safety analysis in virustotal.com. \n"
                    "The program will return analysis results.\n"
                    "-s or --scan | optional | will force new analysis scan."
                    "-a or --apikey | should be followed by your api key."
                    "-m or --max_days | optional | allows you to determine maximum valid days for analysis"
                    " (enter integer). Default: 180",
        epilog="end of help")

    parser.add_argument("urls", nargs='+', help="URLs to scan")  # positional argument - have to
    parser.add_argument("-a", "--apikey", default=None, help='user api key')  # optional
    parser.add_argument("-s", "--scan", action="store_true", help='scan')
    parser.add_argument("-m", "--max_days", default=180, type=int)

    # behind the scene - call the sys.args etc.
    args = parser.parse_args()

    # if are there many urls, split them:
    if ',' in args.urls[0]:
        args.urls = args.urls[0].split(',')

    return args


def main():
    args = get_args()
    api_key = args.apikey

    if args.apikey is None:
        with open('vt_apikey.txt', 'r') as fh:
            api_key = fh.read()

    manager = VtManager(args.urls, args.scan, api_key, args.max_days)

    manager._execute_all()
    manager.update_cache()
    print()
    print('done')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
