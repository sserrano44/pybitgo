__author__ = 'sserrano'
import json
import os

from .bitgo import BitGo

def load_config(filename):
    if os.path.exists(filename):
        try:
           return json.load(open(filename, 'rb'))
        except ValueError:
            return {}
    else:
        return {}

def update_config(filename, cnf):
    config = load_config(filename)
    config.update(cnf)
    json.dump(config, open(filename, "wb"))

def main():
    import getpass
    from optparse import OptionParser
    import sys
    from os.path import expanduser
    home = expanduser("~")

    parser = OptionParser()

    parser.add_option("-a", "--access-token", dest="access_token",
                      help="access token")

    parser.add_option("-w", "--wallet-id", dest="wallet_id",
                      help="wallet id")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        print "a command is required, available: access_token, get_wallets, get_balance, send"
        sys.exit(1)

    action = args[0]
    config_filename = os.path.join(home, ".bitgo")
    config = load_config(config_filename)

    if action == 'access_token':
        username = raw_input('username: ')
        password = getpass.getpass('password: ')
        otp = raw_input('otp: ')
        bitgo = BitGo()
        access_token = bitgo.get_access_token(username, password, otp)
        print "access_token: ", access_token
        if raw_input("store y/n? ") == "y":
            update_config(config_filename, {'access_token': access_token})
        sys.exit(0)

    if options.access_token:
        access_token = options.access_token
    elif 'access_token' in config:
        access_token = config['access_token']
    else:
        print "the --access-token is a required parameter"
        sys.exit(1)

    bitgo = BitGo(access_token=access_token)

    if action == 'get_wallets':
        print bitgo.get_wallets()
    elif action == 'get_balance':
        if options.wallet_id is None:
            print "option -w {{ wallet_id }} is required for get_balance"
            sys.exit(1)
        print bitgo.get_balance(options.wallet_id) / float(10**8)
    elif action == 'get_wallet':
        if options.wallet_id is None:
            print "option -w {{ wallet_id }} is required for get_wallet"
            sys.exit(1)
        otp = getpass.getpass('otp: ')
        bitgo.unlock(otp)
        print bitgo.get_wallet(options.wallet_id)
    elif action == 'get_unspents':
        if options.wallet_id is None:
            print "option -w {{ wallet_id }} is required for get_unspents"
            sys.exit(1)
        print bitgo.get_unspents(options.wallet_id)
    elif action == 'send':
        if options.wallet_id is None:
            print "option -w {{ wallet_id }} is required for send"
            sys.exit(1)
        if len(args) != 3:
            print "address and amount are required"
            sys.exit(1)
        otp = raw_input('otp: ')
        passcode = getpass.getpass('passcode: ')
        bitgo.unlock(otp)
        print bitgo.send(options.wallet_id, passcode, args[1], float(args[2]) * 10**8)
    else:
        print "invalid command"

if __name__ == '__main__':
    main()