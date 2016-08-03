"""

Simple API implementation for BitGo Wallets

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
import requests
import json

from . import sjcl

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
from pycoin.tx.pay_to import address_for_pay_to_script
from pycoin.tx import Tx
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.tx_utils import create_tx
from pycoin.services import get_tx_db
from pycoin.tx import Spendable

from pycoin.tx.pay_to.ScriptMultisig import ScriptMultisig
from pycoin.tx.exceptions import SolvingError
from pycoin.tx.script import tools
from pycoin.tx.script.check_signature import parse_signature_blob
from pycoin import ecdsa
from pycoin import encoding

ScriptMultisig._dummy_signature = lambda x, y: "\x00"

PRODUCTION_URL = "https://www.bitgo.com/api/v1"
TEST_URL = "https://test.bitgo.com/api/v1"

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
    if tx_in.verify(tx_out_script, signature_for_hash_type_f, lock_time=kwargs.get('lock_time')):
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

    def __init__(self, access_token=None, production=True):
        self.access_token = access_token
        self.production=production
        if production:
            self.url = PRODUCTION_URL
        else:
            self.url = TEST_URL

    def get_access_token(self, username, password, otp=None):
        params = {
          'email': username,
          'password': password,
        }
        if otp:
            params['otp'] = otp

        r = requests.post(self.url + '/user/login', params)

        if r.status_code != 200:
            raise Exception('failed request to bitgo %s' % r.content)
        self.access_token = r.json()['access_token']
        return self.access_token

    def get_wallets(self):

        r = requests.get(self.url + '/wallet', headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })

        return r.json()

    def get_wallet(self, wallet_id):
        r = requests.get(self.url + '/wallet/' + wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def get_balance(self, wallet_id, confirmations=0):

        r = requests.get(self.url + '/wallet/%s/unspents' % wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })

        balance = 0
        for tx in r.json()['unspents']:
            if tx['confirmations'] >= confirmations:
                balance += tx['value']

        return balance

    def get_keychain(self, xpub):
        r = requests.post(self.url + '/keychain/%s' % xpub, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def get_unspents(self, wallet_id):
        r = requests.get(self.url + '/wallet/%s/unspents' % wallet_id, headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

    def unlock(self, otp, duration=60):
        r = requests.post(self.url + '/user/unlock', {
                'otp': otp,
                'duration': duration
            }, headers={
                'Authorization': 'Bearer %s' % self.access_token,
            })
        if r.status_code != 200:
            raise BitGoError('unable to unlock\n %s' % r.content)

    def create_address(self, wallet_id, chain=0):
        """

        :param wallet_id: the wallet id :P
        :param chain: 0 for main or 1 change
        :return:
        """
        create_url = "%s/wallet/%s/address/%s" % (
                self.url,
                wallet_id,
                chain
            )

        r = requests.post(create_url, headers={
                'Authorization': 'Bearer %s' % self.access_token,
            })
        if r.status_code != 200:
            raise BitGoError('unable to create address\n %s' % r.content)
        data = r.json()
        return data['address']

    def calculate_fee(self, inputs, outputs, num_blocks=2):
        """

        :param inputs: number of inputs
        :param outputs: number of outputs
        :return: recommended fee in satoshis
        """
        fees_url = "%s/tx/fee?numBlocks=%s" % (self.url, num_blocks)
        r = requests.get(fees_url)
        fee_per_kb = r.json()['feePerKb']

        # poor size estimation - FIXME
        kbytes = 210 * (inputs+outputs) / 1000.0

        return int(fee_per_kb * kbytes)

    def send(self, wallet_id, passcode, address, amount, message='', fee=None, fan_unspend=10):
        """
        Send bitcoins to address

        :param wallet_id: bitgo wallet id
        :param address: bitcoin address
        :param amount: btc amount in satoshis
        :param split: create new outputs if needed
        :return: boolean
        """
        MINIMAL_FEE = 20000
        MINIMAL_SPLIT = 10000000

        wallet = self.get_wallet(wallet_id)

        if not wallet['spendingAccount']:
            raise NotSpendableWallet()

        if not wallet['isActive']:
            raise NotActiveWallet()

        if amount < 10000:
            raise Exception('amount to small')

        if wallet['confirmedBalance'] < amount:
            raise NotEnoughFunds('Not enough funds: balance %s amount %s' %
                                 (wallet['confirmedBalance'], amount)
            )

        change_address = self.create_address(wallet_id, chain=1)
        usableKeychain = False
        spendables = []
        chain_paths = []
        p2sh = []
        payables = [(address, amount)]
        keychain_path = ""

        for keychain in wallet['private']['keychains']:
            keychain_path = keychain['path'][1:]
            keychain = self.get_keychain(keychain['xpub'])
            if 'encryptedXprv' not in keychain:
                continue
            usableKeychain = True
            break

        if not usableKeychain:
            raise BitGoError("didn't found a spendable keychain")

        data = json.loads(keychain['encryptedXprv'])
        #add base64 paddings
        for k in ['iv', 'salt', 'ct']:
            data[k] = data[k] + "=="
        cipher = sjcl.SJCL()
        xprv = cipher.decrypt(data, passcode)

        unspents = self.get_unspents(wallet_id)
        total_value = 0
        for d in unspents['unspents'][::-1]:
            path = keychain_path + d['chainPath']
            chain_paths.append(path)
            p2sh.append(h2b(d["redeemScript"]))
            spendables.append(Spendable(d["value"],
                                  h2b(d["script"]),
                                  h2b_rev(d["tx_hash"]),
                                  d["tx_output_n"]))

            total_value += d['value']
            if total_value > amount:
                break

        # make many outputs?
        if len(unspents['unspents']) < 5 and (total_value > (amount + MINIMAL_SPLIT)) and fan_unspend > 0:
            fee = self.calculate_fee(len(spendables), fan_unspend)
            value = (total_value - amount - fee) / fan_unspend
            for i in range(fan_unspend):
                payables.append((change_address, value))
        elif total_value > (amount + MINIMAL_FEE):
            # add a change address
            if fee is None:
                fee = self.calculate_fee(len(spendables), 2)
            value = total_value - amount - fee
            if value > 10000: #avoid dust
                payables.append((change_address, value))

        p2sh_lookup = build_p2sh_lookup(p2sh)

        spendable_keys = []

        priv_key = BIP32Node.from_hwif(xprv)

        spendable_keys = [priv_key.subkey_for_path(path) for path in chain_paths]

        hash160_lookup = build_hash160_lookup([key.secret_exponent() for key in spendable_keys])

        tx = create_tx(spendables, payables)

        tx.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)

        r = requests.post(self.url + '/tx/send', {
                'tx': tx.as_hex(),
                'message': message
            }, headers={
                'Authorization': 'Bearer %s' % self.access_token,
            })

        return r.json()

    def send_otp(self):
        r = requests.post(self.url + '/user/sendotp', headers={
          'Authorization': 'Bearer %s' % self.access_token,
        })
        return r.json()

