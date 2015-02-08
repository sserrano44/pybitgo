"""

Simple API implementation for BitGo Wallets

"""
import requests
import json
import sjcl_mod as sjcl

from Crypto.Random import random
from pycoin.key.BIP32Node import BIP32Node
from pycoin.tx.Spendable import Spendable
from pycoin.tx import tx_utils
from pycoin.tx.pay_to import build_hash160_lookup, build_p2sh_lookup
from pycoin.serialize import h2b, h2b_rev, b2h, h2b_rev
from pycoin.key.validate import is_address_valid
from pycoin import encoding
from pycoin.serialize import b2h, h2b, stream_to_bytes
from pycoin.key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.networks import NETWORK_NAMES
from pycoin.tx.pay_to import ScriptMultisig, build_p2sh_lookup
from pycoin.tx import Tx
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.tx_utils import create_tx
from pycoin.services import get_tx_db
from pycoin.tx import Spendable

ScriptMultisig._dummy_signature = lambda x, y: "\x00"


URL = "https://www.bitgo.com/api/v1"

def script(num_sigs, all_keys, path):
    """
    Get the redeem script for the path.  The multisig format is (n-1) of n, but can be overridden.
    :param: path: the derivation path
    :type: path: str
    :return: the script
    :rtype: ScriptMultisig
    """
    subkeys = [key.subkey_for_path(path) for key in all_keys]
    secs = [key.sec() for key in subkeys]
    secs.sort()
    script = ScriptMultisig(num_sigs, secs)
    print b2h(encoding.hash160(script.script()))
    return script

def local_sign(tx, scripts, keys, p2sh_lookup):
    #lookup = build_p2sh_lookup([script.script() for script in scripts])
    db = LazySecretExponentDB(map(lambda k: k.wif(), keys), {})
    # FIXME hack to work around broken p2sh signing in pycoin
    #tx.unspents[0].script = script.script()
    return tx.sign(db, p2sh_lookup=p2sh_lookup)

"""
A partially signed transaction looks like:
    OP_0 signature OP_0 redeem_script
where the second OP_0 is a placeholder. This appears to be the de facto
standard. However, pycoin does not use this at the moment. See
https://github.com/richardkiss/pycoin/issues/74
Starting with pycoin version 0.53, this can be easily remedied with the
following code:
    ScriptMultisig._dummy_signature = lambda x, y: "\x00"
However, there is a bug in version 0.52 which prevents this from working.
Below is a workaround.
"""
from pycoin.tx.pay_to.ScriptMultisig import ScriptMultisig
from pycoin.tx.pay_to import SolvingError
from pycoin.tx.script import tools
from pycoin.tx.script.vm import parse_signature_blob
from pycoin import ecdsa
from pycoin import encoding

def solve(self, **kwargs):
    """
    The kwargs required depend upon the script type.
    hash160_lookup:
        dict-like structure that returns a secret exponent for a hash160
    existing_script:
        existing solution to improve upon (optional)
    sign_value:
        the integer value to sign (derived from the transaction hash)
    signature_type:
        usually SIGHASH_ALL (1)
    """
    # we need a hash160 => secret_exponent lookup
    db = kwargs.get("hash160_lookup")
    if db is None:
        raise SolvingError("missing hash160_lookup parameter")

    sign_value = kwargs.get("sign_value")
    signature_type = kwargs.get("signature_type")

    secs_solved = set()
    existing_signatures = []
    existing_script = kwargs.get("existing_script")
    if existing_script:
        pc = 0
        opcode, data, pc = tools.get_opcode(existing_script, pc)
        # ignore the first opcode
        while pc < len(existing_script):
            opcode, data, pc = tools.get_opcode(existing_script, pc)
            sig_pair, actual_signature_type = parse_signature_blob(data)
            for sec_key in self.sec_keys:
                try:
                    public_pair = encoding.sec_to_public_pair(sec_key)
                    sig_pair, signature_type = parse_signature_blob(data)
                    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                    if v:
                        existing_signatures.append(data)
                        secs_solved.add(sec_key)
                        break
                except encoding.EncodingError:
                    # if public_pair is invalid, we just ignore it
                    pass

    for sec_key in self.sec_keys:
        if sec_key in secs_solved:
            continue
        if len(existing_signatures) >= self.n:
            break
        hash160 = encoding.hash160(sec_key)
        result = db.get(hash160)
        if result is None:
            continue
        secret_exponent, public_pair, compressed = result
        binary_signature = self._create_script_signature(secret_exponent, sign_value, signature_type)
        existing_signatures.append(b2h(binary_signature))
    DUMMY_SIGNATURE = "OP_0"
    while len(existing_signatures) < self.n:
        existing_signatures.append(DUMMY_SIGNATURE)

    script = "OP_0 %s" % " ".join(s for s in existing_signatures)
    solution = tools.compile(script)
    return solution

ScriptMultisig.solve = solve

"""
pycoin version 0.52 (and maybe 0.53) do not sign multisig transaction
correctly. See:
https://github.com/richardkiss/pycoin/issues/71
Below is a workaround.
"""

from pycoin.tx.Tx import Tx, SIGHASH_ALL
from pycoin.tx.pay_to import ScriptPayToScript, script_obj_from_script
from pycoin.tx.script import opcodes

byte_to_int = ord if bytes == str else lambda x: x

def sign_tx_in(self, hash160_lookup, tx_in_idx, tx_out_script,
        hash_type=SIGHASH_ALL, **kwargs):
    tx_in = self.txs_in[tx_in_idx]

    is_p2h = (len(tx_out_script) == 23 and byte_to_int(tx_out_script[0]) == opcodes.OP_HASH160 and byte_to_int(tx_out_script[-1]) == opcodes.OP_EQUAL)
    script_to_hash = tx_out_script
    if is_p2h:
        hash160 = ScriptPayToScript.from_script(tx_out_script).hash160
        p2sh_lookup = kwargs.get("p2sh_lookup")
        if p2sh_lookup is None:
            raise ValueError("p2sh_lookup not set")
        if hash160 not in p2sh_lookup:
            raise ValueError("hash160=%s not found in p2sh_lookup" %
                    b2h(hash160))
        script_to_hash = p2sh_lookup[hash160]

    signature_for_hash_type_f = lambda hash_type: self.signature_hash(tx_out_script, tx_in_idx, hash_type)
    if tx_in.verify(tx_out_script, signature_for_hash_type_f):
        return
    sign_value = self.signature_hash(script_to_hash, tx_in_idx, hash_type=hash_type)
    the_script = script_obj_from_script(tx_out_script)
    solution = the_script.solve(hash160_lookup=hash160_lookup, sign_value=sign_value, signature_type=hash_type,existing_script=self.txs_in[tx_in_idx].script, **kwargs)
    tx_in.script = solution

Tx.sign_tx_in = sign_tx_in

class BitGoError(Exception):
    pass

class NotSpendableWallet(BitGoError):
    pass

class NotEnoughFunds(BitGoError):
    pass

class NotActiveWallet(BitGoError):
    pass

class BitGo(object):

    def __init__(self, access_token=None):
        self.access_token = access_token

    def get_access_token(self, username, password, otp=None):
        params = {
          'email': username,
          'password': password,
        }
        if otp:
            params['otp'] = otp

        r = requests.post(URL + '/user/login', params)

        if r.status_code != 200:
            raise Exception('failed request to bitgo %s' % r.content)
        self.access_token = r.json()['access_token']
        return self.access_token

    def get_wallets(self):

        r = requests.get(URL + '/wallet', headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })

        return r.json()

    def get_wallet(self, wallet_id):
        r = requests.get(URL + '/wallet/' + wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def get_balance(self, wallet_id):

        r = requests.get(URL + '/wallet/%s/unspents' % wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })

        balance = 0
        for tx in r.json()['unspents']:
            print tx
            balance += tx['value']

        return balance

    def get_keychain(self, xpub):
        r = requests.post(URL + '/keychain/%s' % xpub, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def get_unspents(self, wallet_id):
        r = requests.get(URL + '/wallet/%s/unspents' % wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def unlock(self, otp, duration=60):
        r = requests.post(URL + '/user/unlock', {
                'otp': otp,
                'duration': duration
            }, headers={
                'Authorization': 'Bearer %s' % self.access_token,
            })
        if r.status_code != 200:
            raise BitGoError('unable to unlock\n %s' % r.content)

    def send(self, wallet_id, passcode, address, amount):
        """
        Send bitcoins to address

        :param wallet_id: bitgo wallet id
        :param address: bitcoin address
        :param amount: btc amount in satoshis
        :return: boolean
        """

        wallet = self.get_wallet(wallet_id)
        if not wallet['spendingAccount']:
            raise NotSpendableWallet()

        if not wallet['isActive']:
            raise NotActiveWallet()

        if wallet['confirmedBalance'] < amount:
            raise NotEnoughFunds('Not enough funds: balance %s amount %s' %
                                 (wallet['confirmedBalance'], amount)
            )

        usableKeychain = False
        for k in wallet['private']['keychains']:
            keychain = self.get_keychain(k['xpub'])
            if 'encryptedXprv' in keychain:
                usableKeychain = True
                break

        if not usableKeychain:
            raise BitGoError("didn't found a spendable keychain")

        data = json.loads(keychain['encryptedXprv'])
        #add base64 paddings
        for k in ['iv', 'salt', 'ct']:
            data[k] = data[k] + "=="

        cipher = sjcl.SJCL()
        print keychain
        xprv = cipher.decrypt(data, passcode)
        print xprv

        keychain_path = keychain['path']

        print "keychain_path", keychain_path

        unspents = self.get_unspents(wallet_id)

        spendables = []
        chain_paths = []
        p2sh = []
        for d in unspents['unspents']:
            chain_paths.append(keychain_path + d['chainPath'])
            p2sh.append(h2b(d["redeemScript"]))
            spendables.append(Spendable.from_dict({"coin_value": d['value'],
                                                   "script_hex": d['script'],
                                                   "tx_hash_hex": d['tx_hash'],
                                                   "tx_out_index": d['tx_output_n']}))

        p2sh_lookup = build_p2sh_lookup(p2sh)
        pub_keys = []
        for keychain in wallet['private']['keychains']:
            pub_keys.append(BIP32Node.from_text(keychain['xpub']))

        priv_key = BIP32Node.from_text(xprv)
        priv_sub_keys = []
        scripts = []

        for path in chain_paths:
            print path
            if path.startswith("m/"):
                path = path[2:]
            scripts.append(script(3, pub_keys, path))
            priv_sub_keys.append(priv_key.subkey_for_path(path))

        tx = create_tx(spendables, [(address, amount)])

        tx = local_sign(tx, scripts, priv_sub_keys, p2sh_lookup)

        print tx.as_hex()

        r = requests.post(URL + '/tx/send', {
                'tx': tx.as_hex(),
            }, headers={
                'Authorization': 'Bearer %s' % self.access_token,
            })
        print r.content

if __name__ == '__main__':
    import getpass
    from optparse import OptionParser
    import sys

    parser = OptionParser()

    parser.add_option("-a", "--access-token", dest="access_token",
                      help="access token")

    parser.add_option("-w", "--wallet-id", dest="wallet_id",
                      help="wallet id")

    (options, args) = parser.parse_args()

    print options
    print args

    bitgo = BitGo(access_token=options.access_token)

    if len(args) == 0:
        print "a command is required, available: access_token, get_wallets, get_balance, send"

    if args[0] == 'access_token':
        username = raw_input('username: ')
        password = getpass.getpass('password: ')
        otp = raw_input('otp: ')
        print "access_token: ", bitgo.get_access_token(username, password, otp)
    elif args[0] == 'get_wallets':
        print bitgo.get_wallets()
    elif args[0] == 'get_balance':
        if options.wallet_id is None:
            print "option --wallet_id is required for get_balance"
            sys.exit(1)
        print bitgo.get_balance(options.wallet_id) / float(10**8)
    elif args[0] == 'get_wallet':
        if options.wallet_id is None:
            print "option --wallet_id is required for get_balance"
            sys.exit(1)
        otp = getpass.getpass('otp: ')
        bitgo.unlock(otp)
        print bitgo.get_wallet(options.wallet_id)
    elif args[0] == 'get_unspents':
        if options.wallet_id is None:
            print "option --wallet_id is required for get_balance"
            sys.exit(1)
        print bitgo.get_unspents(options.wallet_id)
    elif args[0] == 'send':
        if options.wallet_id is None:
            print "option --wallet_id is required for get_balance"
            sys.exit(1)
        if len(args) != 3:
            print "address and amount are required"
            sys.exit(1)
        otp = getpass.getpass('otp: ')
        passcode = getpass.getpass('passcode: ')
        bitgo.unlock(otp)
        bitgo.send(options.wallet_id, passcode, args[1], float(args[2]) * 10**8)
    else:
        print "invalid command"
