#!/usr/bin/env python3

import sys, logging
import requests, json, argparse, textwrap
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from oracle_casb_api import *


parser = argparse.ArgumentParser(
prog='Oracle CASB API Client',
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog=textwrap.dedent('''\
     ./OCCS_api_client.py: an API client impelmentation to fetch Oracle CASB Events and reports. It then parses it and sends it as syslog to a Syslog server/SIEM Solution
     '''))
parser.add_argument('-s', '--syslog-server',type=str, required=True, help="Syslog Server where to send the fetched OCCS data as syslog")
parser.add_argument('-b', '--base-url',type=str, required=True, help="Oracle CASB base url, typically https://XXXXXXXX.palerra.net")
parser.add_argument('-k', '--access-key',type=str, required=True, help="Oracle CASB Access Key")
parser.add_argument('-a', '--access-secret',type=str, required=True, help='Oracle CASB Access Secret')
parser.add_argument('-t', '--time-period',type=int, required=True, help='time period of the events expressed as number of days, exp: 7 would fetch the events of the past week')

args = parser.parse_args()

logger = logging.getLogger('OCCS_Logger')
logger.setLevel(logging.ERROR)


ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def occs_init():
    try:
        occs = occs_api.OracleCasbCS(
            base_url=args.base_url, 
            access_key = args.access_key,
            access_secret = args.access_secret,
            verify_ssl=False,
            logger = logger
            )
        return occs
    except Exception as e:
        print("Failed to connect: {}".format(e))
        sys.exit(1)


occs_object=occs_init()

startDate = arrow.now().shift(days=(-1 * args.time_period)).format('YYYY-MM-DDTHH:mm:ss.SSS')
res = occs_object.get_risk_events(startDate)
send_syslog(args.syslog_server,(json_to_syslog_ready(res)))

