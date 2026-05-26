#!/usr/bin/env python3
"""
Wazuh Custom Integration: Agentix Gateway Direct Forward
=========================================================
Sends Wazuh alerts directly to the Agentix Gateway webhook
endpoint with X-Internal-Api-Key auth.

ossec.conf usage:
  <integration>
    <name>custom-agentix</name>
    <hook_url>http://agentix-gateway:8001/v1/webhooks/wazuh</hook_url>
    <api_key>dev-internal-key-change-me-in-production</api_key>
    <group>authentication_failures</group>
    <alert_format>json</alert_format>
  </integration>

Error Codes:
  1 - Module requests not found
  2 - Incorrect input arguments
  6 - Alert file not found
  7 - Invalid JSON
"""

import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Argument indices (Wazuh integration convention)
ALERT_INDEX = 1
APIKEY_INDEX = 2
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        bad_arguments = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3],
                args[4] if len(args) > 4 else '',
                args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args):
    """Core function: reads alert, builds payload, sends to Agentix Gateway."""
    debug('# Running Agentix custom integration script')

    alert_file_location = args[ALERT_INDEX]
    api_key = args[APIKEY_INDEX]
    webhook = args[WEBHOOK_INDEX]

    # Load alert JSON
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Alert loaded from '{alert_file_location}'")

    # Build message payload for compatibility with agentix webhook handler
    msg = generate_msg(json_alert)
    if not msg:
        return

    debug(f'# Sending message to Agentix Gateway: {webhook}')
    send_msg(msg, webhook, api_key)


def debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def generate_msg(alert):
    """Generate the JSON payload compatible with Agentix webhook handler."""
    level = alert.get('rule', {}).get('level', 0)

    if level <= 4:
        severity = 1
    elif 5 <= level <= 7:
        severity = 2
    else:
        severity = 3

    msg = {
        'severity': severity,
        'pretext': 'WAZUH Alert',
        'title': alert.get('rule', {}).get('description', 'N/A'),
        'text': alert.get('full_log', ''),
        'rule_id': alert.get('rule', {}).get('id', ''),
        'timestamp': alert.get('timestamp', ''),
        'id': alert.get('id', ''),
        'all_fields': alert,
    }

    return json.dumps(msg)


def send_msg(msg, url, api_key):
    """Send the alert payload to Agentix Gateway with X-Internal-Api-Key auth."""
    headers = {
        'Content-Type': 'application/json',
        'Accept-Charset': 'UTF-8',
        'X-Internal-Api-Key': api_key,
    }
    try:
        res = requests.post(url, data=msg, headers=headers, timeout=10)
        debug(f'# Response: status={res.status_code} body={res.text[:200]}')
    except Exception as e:
        debug(f'# Error sending to Agentix: {e}')


def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
