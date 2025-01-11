# duopwn

A security assessment tool for Duo MFA implementations that uses the Duo Auth API to test various authentication mechanisms. For authorized penetration testing use only.

## Features

- User enumeration through preauth endpoint
- Device ID retrieval for enrolled users
- Multiple auth factor support:
  - Push notifications
  - Phone calls
  - SMS passcodes
  - OTP/passcodes
- Auth status checking with transaction IDs
- Lockout testing with configurable attempts

## Installation

```bash
git clone https://github.com/yourusername/duopwn.git
cd duopwn
pip install -r requirements.txt
```

## Usage

Basic command structure:
```bash
python duopwn.py -U <api-hostname> -i <integration-key> -s <secret-key> -A <action> [options]
```

### Examples

1. Enumerate users from a list:
```bash
python duopwn.py -U api-xyz.duosecurity.com -i IKEY -s SKEY -l users.txt
```

2. Force a push notification:
```bash
python duopwn.py -U api-xyz.duosecurity.com -i IKEY -s SKEY -u username -A auth -d DEVICE_ID -f push
```

3. Test account lockout:
```bash
python duopwn.py -U api-xyz.duosecurity.com -i IKEY -s SKEY -u username -A lockout --attempts 5
```

4. Check auth status:
```bash
python duopwn.py -U api-xyz.duosecurity.com -i IKEY -s SKEY -u username -A auth_status -t TXID
```

### Available Actions

- `ping`: Test API connectivity
- `check`: Verify integration key
- `enroll`: Start enrollment process
- `enroll_status`: Check enrollment status
- `preauth`: Check user enrollment and get device info
- `auth`: Initiate authentication
- `auth_status`: Check authentication status
- `lockout`: Test account lockout mechanisms

### Options

- `-U, --url`: Duo API hostname
- `-i, --ikey`: Integration key
- `-s, --skey`: Secret key
- `-u, --user`: Single username
- `-l, --list`: File containing usernames
- `-d, --device`: Device ID (from preauth)
- `-f, --factor`: Auth factor (push/phone/sms/passcode)
- `-p, --passcode`: OTP/passcode value
- `-t, --txid`: Transaction ID for status checks
- `--attempts`: Number of attempts for lockout testing

## Legal Disclaimer

This tool is for authorized penetration testing and security research only. Users must ensure they have explicit permission to test the target Duo implementation. Unauthorized testing may violate applicable laws.

## References

- [Duo Auth API Documentation](https://duo.com/docs/authapi)
- [Abusing Duo Authentication Misconfigurations](https://www.mandiant.com/resources/blog/abusing-duo-authentication-misconfigurations)
