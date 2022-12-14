# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Wallet classes:
#   - Imported_Wallet: imported address, no keystore
#   - Standard_Wallet: one keystore, P2PKH
#   - Multisig_Wallet: several keystores, P2SH

import os
import sys
import random
import time
import json
import copy
import errno
import traceback
import operator
from functools import partial
from collections import defaultdict
from numbers import Number
from decimal import Decimal
from typing import TYPE_CHECKING, List, Optional, Tuple, Union, NamedTuple, Sequence, Dict, Any, Set

from .i18n import _
from .bip32 import BIP32Node
from .crypto import sha256
from .util import (NotEnoughFunds, UserCancelled, profiler,
                   format_satoshis, format_fee_satoshis, NoDynamicFeeEstimates,
                   WalletFileException, BitcoinException,
                   InvalidPassword, format_time, timestamp_to_datetime, Satoshis,
                   Fiat, bfh, bh2u, TxMinedInfo, quantize_feerate, create_bip21_uri, OrderedDictWithIndex)
from .util import PR_TYPE_ONCHAIN, PR_TYPE_LN
from .simple_config import SimpleConfig
from .bitcoin import (COIN, is_address, address_to_script,
                      is_minikey, relayfee, dust_threshold)
from .crypto import sha256d
from . import keystore
from .keystore import load_keystore, Hardware_KeyStore, KeyStore
from .util import multisig_type
from .storage import StorageEncryptionVersion, WalletStorage
from . import transaction, bitcoin, coinchooser, paymentrequest, ecc, bip32
from .transaction import (Transaction, TxInput, UnknownTxinType, TxOutput,
                          PartialTransaction, PartialHsmTransaction, PartialBip32HsmTransaction, PartialDAPTransaction, PartialTxInput, PartialTxOutput, TxOutpoint)
from .plugin import run_hook
from .address_synchronizer import (AddressSynchronizer, TX_HEIGHT_LOCAL,
                                   TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_FUTURE)
from .util import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED, PR_INFLIGHT
from .contacts import Contacts
from .interface import NetworkException
from .ecc_fast import is_using_fast_ecc
from .mnemonic import Mnemonic
from .logging import get_logger
from .lnworker import LNWallet
from .paymentrequest import PaymentRequest

if TYPE_CHECKING:
    from .network import Network


_logger = get_logger(__name__)

TX_STATUS = [
    _('Unconfirmed'),
    _('Unconfirmed parent'),
    _('Not Verified'),
    _('Local'),
]


def _append_utxos_to_inputs(inputs: List[PartialTxInput], network: 'Network', pubkey, txin_type, imax):
    if txin_type in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
        address = bitcoin.pubkey_to_address(txin_type, pubkey)
        scripthash = bitcoin.address_to_scripthash(address)
    elif txin_type == 'p2pk':
        script = bitcoin.public_key_to_p2pk_script(pubkey)
        scripthash = bitcoin.script_to_scripthash(script)
        address = None
    else:
        raise Exception(f'unexpected txin_type to sweep: {txin_type}')

    u = network.run_from_another_thread(network.listunspent_for_scripthash(scripthash))
    for item in u:
        if len(inputs) >= imax:
            break
        prevout_str = item['tx_hash'] + ':%d' % item['tx_pos']
        prevout = TxOutpoint.from_str(prevout_str)
        utxo = PartialTxInput(prevout=prevout)
        utxo._trusted_value_sats = int(item['value'])
        utxo._trusted_address = address
        utxo.block_height = int(item['height'])
        utxo.script_type = txin_type
        utxo.pubkeys = [bfh(pubkey)]
        utxo.num_sig = 1
        if txin_type == 'p2wpkh-p2sh':
            utxo.redeem_script = bfh(bitcoin.p2wpkh_nested_script(pubkey))
        inputs.append(utxo)

def sweep_preparations(privkeys, network: 'Network', imax=100):

    def find_utxos_for_privkey(txin_type, privkey, compressed):
        pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        _append_utxos_to_inputs(inputs, network, pubkey, txin_type, imax)
        keypairs[pubkey] = privkey, compressed
    inputs = []  # type: List[PartialTxInput]
    keypairs = {}
    for sec in privkeys:
        txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
        find_utxos_for_privkey(txin_type, privkey, compressed)
        # do other lookups to increase support coverage
        if is_minikey(sec):
            # minikeys don't have a compressed byte
            # we lookup both compressed and uncompressed pubkeys
            find_utxos_for_privkey(txin_type, privkey, not compressed)
        elif txin_type == 'p2pkh':
            # WIF serialization does not distinguish p2pkh and p2pk
            # we also search for pay-to-pubkey outputs
            find_utxos_for_privkey('p2pk', privkey, compressed)
    if not inputs:
        raise Exception(_('No inputs found. (Note that inputs need to be confirmed)'))
        # FIXME actually inputs need not be confirmed now, see https://github.com/kyuupichan/electrumx/issues/365
    return inputs, keypairs


def sweep(privkeys, *, network: 'Network', config: 'SimpleConfig',
          to_address: str, fee: int = None, imax=100,
          locktime=None, tx_version=None) -> PartialTransaction:
    print('wallet:sweep to_address={} fee={}'.format(to_address, fee))
    inputs, keypairs = sweep_preparations(privkeys, network, imax)
    total = sum(txin.value_sats() for txin in inputs)
    if fee is None:
        outputs = [PartialTxOutput(scriptpubkey=bfh(bitcoin.address_to_script(to_address)),
                                   value=total)]
        tx = PartialTransaction.from_io(inputs, outputs)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise Exception(_('Not enough funds on address.') + '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d'%(total, fee, dust_threshold(network)))

    outputs = [PartialTxOutput(scriptpubkey=bfh(bitcoin.address_to_script(to_address)),
                               value=total - fee)]
    if locktime is None:
        locktime = get_locktime_for_new_transaction(network)

    tx = PartialTransaction.from_io(inputs, outputs, locktime=locktime, version=tx_version)
    tx.set_rbf(True)
    tx.sign(keypairs)
    return tx


def get_locktime_for_new_transaction(network: 'Network') -> int:
    # if no network or not up to date, just set locktime to zero
    if not network:
        return 0
    chain = network.blockchain()
    header = chain.header_at_tip()
    if not header:
        return 0
    STALE_DELAY = 8 * 60 * 60  # in seconds
    if header['timestamp'] + STALE_DELAY < time.time():
        return 0
    # discourage "fee sniping"
    locktime = chain.height()
    # sometimes pick locktime a bit further back, to help privacy
    # of setups that need more time (offline/multisig/coinjoin/...)
    if random.randint(0, 9) == 0:
        locktime = max(0, locktime - random.randint(0, 99))
    return locktime



class CannotBumpFee(Exception): pass


class InternalAddressCorruption(Exception):
    def __str__(self):
        return _("Wallet file corruption detected. "
                 "Please restore your wallet from seed, and compare the addresses in both files")


class TxWalletDetails(NamedTuple):
    txid: Optional[str]
    status: str
    label: str
    can_broadcast: bool
    can_bump: bool
    can_save_as_local: bool
    amount: Optional[int]
    fee: Optional[int]
    tx_mined_status: TxMinedInfo
    mempool_depth_bytes: Optional[int]


class Abstract_Wallet(AddressSynchronizer):
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    LOGGING_SHORTCUT = 'w'
    max_change_outputs = 3
    gap_limit_for_change = 6

    txin_type: str
    wallet_type: str

    def __init__(self, storage: WalletStorage, *, config: SimpleConfig):
        if not storage.is_ready_to_be_used_by_wallet():
            raise Exception("storage not ready to be used by Abstract_Wallet")

        self.config = config
        assert self.config is not None, "config must not be None"
        self.storage = storage
        # load addresses needs to be called before constructor for sanity checks
        self.storage.db.load_addresses(self.wallet_type)
        self.keystore = None  # type: Optional[KeyStore]  # will be set by load_keystore
        AddressSynchronizer.__init__(self, storage.db)

        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = set(storage.get('frozen_addresses', []))
        self.frozen_coins          = set(storage.get('frozen_coins', []))  # set of txid:vout strings
        self.fiat_value            = storage.get('fiat_value', {})
        self.receive_requests      = storage.get('payment_requests', {})
        self.invoices              = storage.get('invoices', {})
        # convert invoices
        # TODO invoices being these contextual dicts even internally,
        #      where certain keys are only present depending on values of other keys...
        #      it's horrible. we need to change this, at least for the internal representation,
        #      to something that can be typed.
        for invoice_key, invoice in self.invoices.items():
            if invoice.get('type') == PR_TYPE_ONCHAIN:
                outputs = [PartialTxOutput.from_legacy_tuple(*output) for output in invoice.get('outputs')]
                invoice['outputs'] = outputs
        self._prepare_onchain_invoice_paid_detection()
        self.calc_unused_change_addresses()
        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)
        self.contacts = Contacts(self.storage)
        self._coin_price_cache = {}
        # lightning
        ln_xprv = self.storage.get('lightning_privkey2')
        self.lnworker = LNWallet(self, ln_xprv) if ln_xprv else None

    def has_lightning(self):
        print('wallet:Abstract_Wallet:has_lightning lnworker={}'.format(self.lnworker))
        return bool(self.lnworker)

    def init_lightning(self):
        print('wallet:Abstract_Wallet:init_lightning')
        if self.storage.get('lightning_privkey2'):
            return
        if not is_using_fast_ecc():
            raise Exception('libsecp256k1 library not available. '
                            'Verifying Lightning channels is too computationally expensive without libsecp256k1, aborting.')
        # TODO derive this deterministically from wallet.keystore at keystore generation time
        # probably along a hardened path ( lnd-equivalent would be m/1017'/coinType'/ )
        seed = os.urandom(32)
        print('wallet:init_lightning: seed={}'.format(seed))
        node = BIP32Node.from_rootseed(seed, xtype='standard')
        ln_xprv = node.to_xprv()
        self.storage.put('lightning_privkey2', ln_xprv)
        self.storage.write()

    def remove_lightning(self):
        print('wallet:Abstract_Wallet:remove_lightning')
        if not self.storage.get('lightning_privkey2'):
            return
        if bool(self.lnworker.channels):
            raise Exception('Error: This wallet has channels')
        self.storage.put('lightning_privkey2', None)
        self.storage.write()

    def stop_threads(self):
        print('wallet:Abstract_Wallet:stop_threads')
        super().stop_threads()
        if any([ks.is_requesting_to_be_rewritten_to_wallet_file for ks in self.get_keystores()]):
            self.save_keystore()
        self.storage.write()

    def set_up_to_date(self, b):
        print('wallet:Abstract_Wallet:set_up_to_date')
        super().set_up_to_date(b)
        if b: self.storage.write()

    def clear_history(self):
        print('wallet:Abstract_Wallet:clear_history')
        super().clear_history()
        self.storage.write()

    def start_network(self, network):
        print('wallet:Abstract_wallet:start_network network={}'.format(network))
        AddressSynchronizer.start_network(self, network)
        if self.lnworker:
            network.maybe_init_lightning()
            self.lnworker.start_network(network)

    def load_and_cleanup(self):
        print('wallet:Abstract_Wallet:load_and_cleanup')
        self.load_keystore()
        self.test_addresses_sanity()
        super().load_and_cleanup()

    def load_keystore(self) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def diagnostic_name(self):
        return self.basename()

    def __str__(self):
        return self.basename()

    def get_master_public_key(self):
        return None

    def get_master_public_keys(self):
        return []

    def basename(self) -> str:
        return os.path.basename(self.storage.path)

    def test_addresses_sanity(self):
        print('wallet:Abstract_Wallet:test_addresses_sanity')
        addrs = self.get_receiving_addresses()
        if len(addrs) > 0:
            addr = str(addrs[0])
            if not bitcoin.is_address(addr):
                neutered_addr = addr[:5] + '..' + addr[-2:]
                raise WalletFileException(f'The addresses in this wallet are not bitcoin addresses.\n'
                                          f'e.g. {neutered_addr} (length: {len(addr)})')

    def calc_unused_change_addresses(self):
        print('wallet:Abstract_Wallet:calc_unused_change_addresses')
        with self.lock:
            if hasattr(self, '_unused_change_addresses'):
                addrs = self._unused_change_addresses
            else:
                addrs = self.get_change_addresses()
            self._unused_change_addresses = [addr for addr in addrs if
                                            self.get_address_history_len(addr) == 0]
            return list(self._unused_change_addresses)

    def is_deterministic(self):
        print('wallet:Abstract_Wallet:is_deteministic')
        return self.keystore.is_deterministic()

    def set_label(self, name, text = None):
        print('wallet:Abstract_Wallet:set_label')
        changed = False
        old_text = self.labels.get(name)
        if text:
            text = text.replace("\n", " ")
            if old_text != text:
                self.labels[name] = text
                changed = True
        else:
            if old_text is not None:
                self.labels.pop(name)
                changed = True
        if changed:
            run_hook('set_label', self, name, text)
            self.storage.put('labels', self.labels)
        return changed

    def set_fiat_value(self, txid, ccy, text, fx, value_sat):
        print('wallet:Abstract_Wallet:set_fiat_value')
        if not self.db.get_transaction(txid):
            return
        # since fx is inserting the thousands separator,
        # and not util, also have fx remove it
        text = fx.remove_thousands_separator(text)
        def_fiat = self.default_fiat_value(txid, fx, value_sat)
        formatted = fx.ccy_amount_str(def_fiat, commas=False)
        def_fiat_rounded = Decimal(formatted)
        reset = not text
        if not reset:
            try:
                text_dec = Decimal(text)
                text_dec_rounded = Decimal(fx.ccy_amount_str(text_dec, commas=False))
                reset = text_dec_rounded == def_fiat_rounded
            except:
                # garbage. not resetting, but not saving either
                return False
        if reset:
            d = self.fiat_value.get(ccy, {})
            if d and txid in d:
                d.pop(txid)
            else:
                # avoid saving empty dict
                return True
        else:
            if ccy not in self.fiat_value:
                self.fiat_value[ccy] = {}
            self.fiat_value[ccy][txid] = text
        self.storage.put('fiat_value', self.fiat_value)
        return reset

    def get_fiat_value(self, txid, ccy):
        print('wallet:Abstract_Wallet:get_fiat_value')
        fiat_value = self.fiat_value.get(ccy, {}).get(txid)
        try:
            return Decimal(fiat_value)
        except:
            return

    def is_mine(self, address) -> bool:
        # print('wallet:Abstract_Wallet:is_mine')
        return bool(self.get_address_index(address))

    def is_change(self, address) -> bool:
        print('wallet:Abstract_Wallet:is_change')
        if not self.is_mine(address):
            return False
        return self.get_address_index(address)[0] == 1

    def get_address_index(self, address):
        raise NotImplementedError()

    def get_redeem_script(self, address: str) -> Optional[str]:
        print('wallet:Abstract_Wallet:get_redeem_script')
        txin_type = self.get_txin_type(address)
        if txin_type in ('p2pkh', 'p2wpkh', 'p2pk'):
            return None
        if txin_type == 'p2wpkh-p2sh':
            pubkey = self.get_public_key(address)
            return bitcoin.p2wpkh_nested_script(pubkey)
        if txin_type == 'address':
            return None
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def get_witness_script(self, address: str) -> Optional[str]:
        print('wallet:Abstract_Wallet:get_witness_script')
        return None

    def get_txin_type(self, address: str) -> str:
        """Return script type of wallet address."""
        raise NotImplementedError()

    def export_private_key(self, address, password) -> str:
        print('wallet:Abstract_Wallet:export_private_key')
        if self.is_watching_only():
            raise Exception(_("This is a watching-only wallet"))
        if not is_address(address):
            raise Exception(f"Invalid bitcoin address: {address}")
        if not self.is_mine(address):
            raise Exception(_('Address not in wallet.') + f' {address}')
        index = self.get_address_index(address)
        pk, compressed = self.keystore.get_private_key(index, password)
        txin_type = self.get_txin_type(address)
        serialized_privkey = bitcoin.serialize_privkey(pk, compressed, txin_type)
        return serialized_privkey

    def get_public_keys(self, address):
        print('wallet:Abstract_Wallet:get_public_keys')
        return [self.get_public_key(address)]

    def get_public_keys_with_deriv_info(self, address: str) -> Dict[str, Tuple[KeyStore, Sequence[int]]]:
        """Returns a map: pubkey_hex -> (keystore, derivation_suffix)"""
        print('wallet:Abstract_Wallet:get_public_keys_with_deriv_info')
        return {}

    def is_found(self):
        print('wallet:Abstract_Wallet:is_found')
        return True
        #return self.history.values() != [[]] * len(self.history)

    def get_tx_info(self, tx) -> TxWalletDetails:
        print('wallet:Abstract_Wallet:get_tx_info')
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        if fee is None and isinstance(tx, PartialTransaction):
            fee = tx.get_fee()
        exp_n = None
        can_broadcast = False
        can_bump = False
        can_save_as_local = False
        label = ''
        tx_hash = tx.txid()
        tx_mined_status = self.get_tx_height(tx_hash)
        if tx.is_complete():
            if self.db.get_transaction(tx_hash):
                label = self.get_label(tx_hash)
                if tx_mined_status.height > 0:
                    if tx_mined_status.conf:
                        status = _("{} confirmations").format(tx_mined_status.conf)
                    else:
                        status = _('Not verified')
                elif tx_mined_status.height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED):
                    status = _('Unconfirmed')
                    if fee is None:
                        fee = self.get_tx_fee(tx_hash)
                    if fee and self.network and self.config.has_fee_mempool():
                        size = tx.estimated_size()
                        fee_per_byte = fee / size
                        exp_n = self.config.fee_to_depth(fee_per_byte)
                    can_bump = is_mine and not tx.is_final()
                else:
                    status = _('Local')
                    can_broadcast = self.network is not None
                    can_bump = is_mine and not tx.is_final()
            else:
                status = _("Signed")
                can_broadcast = self.network is not None
                can_save_as_local = is_relevant
        else:
            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if is_relevant:
            if is_mine:
                if fee is not None:
                    amount = v + fee
                else:
                    amount = v
            else:
                amount = v
        else:
            amount = None

        return TxWalletDetails(
            txid=tx_hash,
            status=status,
            label=label,
            can_broadcast=can_broadcast,
            can_bump=can_bump,
            can_save_as_local=can_save_as_local,
            amount=amount,
            fee=fee,
            tx_mined_status=tx_mined_status,
            mempool_depth_bytes=exp_n,
        )

    def get_spendable_coins(self, domain, *, nonlocal_only=False) -> Sequence[PartialTxInput]:
        print('wallet:Abstract_Wallet:get_spendable_coins')
        confirmed_only = self.config.get('confirmed_only', False)
        utxos = self.get_utxos(domain,
                               excluded_addresses=self.frozen_addresses,
                               mature_only=True,
                               confirmed_only=confirmed_only,
                               nonlocal_only=nonlocal_only)
        utxos = [utxo for utxo in utxos if not self.is_frozen_coin(utxo)]
        print('wallet:Abstract_Wallet:get_spendable_coins utxos={}'.format(utxos))
        return utxos

    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence[str]:
        raise NotImplementedError()  # implemented by subclasses

    def get_change_addresses(self, *, slice_start=None, slice_stop=None) -> Sequence[str]:
        raise NotImplementedError()  # implemented by subclasses

    def dummy_address(self):
        print('wallet:Abstract_Wallet:dummy_address')
        # first receiving address
        return self.get_receiving_addresses(slice_start=0, slice_stop=1)[0]

    def get_frozen_balance(self):
        print('wallet:Abstract_Wallet:get_frozen_balance')
        if not self.frozen_coins:  # shortcut
            return self.get_balance(self.frozen_addresses)
        c1, u1, x1 = self.get_balance()
        c2, u2, x2 = self.get_balance(excluded_addresses=self.frozen_addresses,
                                      excluded_coins=self.frozen_coins)
        return c1-c2, u1-u2, x1-x2

    def balance_at_timestamp(self, domain, target_timestamp):
        print('wallet:Abstract_Wallet:balance_at_timestamp')
        # we assume that get_history returns items ordered by block height
        # we also assume that block timestamps are monotonic (which is false...!)
        h = self.get_history(domain=domain)
        balance = 0
        for hist_item in h:
            balance = hist_item.balance
            if hist_item.tx_mined_status.timestamp is None or hist_item.tx_mined_status.timestamp > target_timestamp:
                return balance - hist_item.delta
        # return last balance
        return balance

    def get_onchain_history(self, *, domain=None):
        print('wallet:Abstract_Wallet:get_onchain_history')
        for hist_item in self.get_history(domain=domain):
            yield {
                'txid': hist_item.txid,
                'fee_sat': hist_item.fee,
                'height': hist_item.tx_mined_status.height,
                'confirmations': hist_item.tx_mined_status.conf,
                'timestamp': hist_item.tx_mined_status.timestamp,
                'incoming': True if hist_item.delta>0 else False,
                'bc_value': Satoshis(hist_item.delta),
                'bc_balance': Satoshis(hist_item.balance),
                'date': timestamp_to_datetime(hist_item.tx_mined_status.timestamp),
                'label': self.get_label(hist_item.txid),
                'txpos_in_block': hist_item.tx_mined_status.txpos,
            }

    def create_invoice(self, outputs: List[PartialTxOutput], message, pr, URI):
        print('wallet:Abstract_Wallet:create_invoice')
        if '!' in (x.value for x in outputs):
            amount = '!'
        else:
            amount = sum(x.value for x in outputs)
        invoice = {
            'type': PR_TYPE_ONCHAIN,
            'message': message,
            'outputs': outputs,
            'amount': amount,
        }
        if pr:
            invoice['bip70'] = pr.raw.hex()
            invoice['time'] = pr.get_time()
            invoice['exp'] = pr.get_expiration_date() - pr.get_time()
            invoice['requestor'] = pr.get_requestor()
            invoice['message'] = pr.get_memo()
        elif URI:
            timestamp = URI.get('time')
            if timestamp: invoice['time'] = timestamp
            exp = URI.get('exp')
            if exp: invoice['exp'] = exp
        if 'time' not in invoice:
            invoice['time'] = int(time.time())
        return invoice

    def save_invoice(self, invoice):
        print('wallet:Abstract_Wallet:save_invoice')
        invoice_type = invoice['type']
        if invoice_type == PR_TYPE_LN:
            key = invoice['rhash']
        elif invoice_type == PR_TYPE_ONCHAIN:
            key = bh2u(sha256(repr(invoice))[0:16])
            invoice['id'] = key
            outputs = invoice['outputs']  # type: List[PartialTxOutput]
            with self.transaction_lock:
                for txout in outputs:
                    self._invoices_from_scriptpubkey_map[txout.scriptpubkey].add(key)
        else:
            raise Exception('Unsupported invoice type')
        self.invoices[key] = invoice
        self.storage.put('invoices', self.invoices)
        self.storage.write()

    def clear_invoices(self):
        print('wallet:Abstract_Wallet:clear_invoices')
        self.invoices = {}
        self.storage.put('invoices', self.invoices)
        self.storage.write()

    def get_invoices(self):
        print('wallet:Abstract_Wallet:get_invoices')
        out = [self.get_invoice(key) for key in self.invoices.keys()]
        out = list(filter(None, out))
        out.sort(key=operator.itemgetter('time'))
        return out

    def get_invoice(self, key):
        print('wallet:Abstract_Wallet:get_invoice')
        if key not in self.invoices:
            return
        item = copy.copy(self.invoices[key])
        request_type = item.get('type')
        if request_type == PR_TYPE_ONCHAIN:
            item['status'] = PR_PAID if self._is_onchain_invoice_paid(item)[0] else PR_UNPAID
        elif self.lnworker and request_type == PR_TYPE_LN:
            item['status'] = self.lnworker.get_payment_status(bfh(item['rhash']))
        else:
            return
        return item

    def _get_relevant_invoice_keys_for_tx(self, tx: Transaction) -> Set[str]:
        relevant_invoice_keys = set()
        for txout in tx.outputs():
            for invoice_key in self._invoices_from_scriptpubkey_map.get(txout.scriptpubkey, set()):
                relevant_invoice_keys.add(invoice_key)
        return relevant_invoice_keys

    def _prepare_onchain_invoice_paid_detection(self):
        # scriptpubkey -> list(invoice_keys)
        self._invoices_from_scriptpubkey_map = defaultdict(set)  # type: Dict[bytes, Set[str]]
        for invoice_key, invoice in self.invoices.items():
            if invoice.get('type') == PR_TYPE_ONCHAIN:
                outputs = invoice['outputs']  # type: List[PartialTxOutput]
                for txout in outputs:
                    self._invoices_from_scriptpubkey_map[txout.scriptpubkey].add(invoice_key)

    def _is_onchain_invoice_paid(self, invoice) -> Tuple[bool, Sequence[str]]:
        """Returns whether on-chain invoice is satisfied, and list of relevant TXIDs."""
        assert invoice.get('type') == PR_TYPE_ONCHAIN
        invoice_amounts = defaultdict(int)  # type: Dict[bytes, int]  # scriptpubkey -> value_sats
        for txo in invoice['outputs']:  # type: PartialTxOutput
            invoice_amounts[txo.scriptpubkey] += 1 if txo.value == '!' else txo.value
        relevant_txs = []
        with self.transaction_lock:
            for invoice_scriptpubkey, invoice_amt in invoice_amounts.items():
                scripthash = bitcoin.script_to_scripthash(invoice_scriptpubkey.hex())
                prevouts_and_values = self.db.get_prevouts_by_scripthash(scripthash)
                relevant_txs += [prevout.txid.hex() for prevout, v in prevouts_and_values]
                total_received = sum([v for prevout, v in prevouts_and_values])
                if total_received < invoice_amt:
                    return False, []
        return True, relevant_txs

    def _maybe_set_tx_label_based_on_invoices(self, tx: Transaction) -> bool:
        tx_hash = tx.txid()
        with self.transaction_lock:
            labels = []
            for invoice_key in self._get_relevant_invoice_keys_for_tx(tx):
                invoice = self.invoices.get(invoice_key)
                if invoice is None: continue
                assert invoice.get('type') == PR_TYPE_ONCHAIN
                if invoice['message']:
                    labels.append(invoice['message'])
        if labels:
            self.set_label(tx_hash, "; ".join(labels))
        return bool(labels)

    def add_transaction(self, tx, *, allow_unrelated=False):
        print('wallet:Abstract_Wallet:add_transaction')
        tx_was_added = super().add_transaction(tx, allow_unrelated=allow_unrelated)

        if tx_was_added:
            self._maybe_set_tx_label_based_on_invoices(tx)
        return tx_was_added

    @profiler
    def get_full_history(self, fx=None, *, onchain_domain=None, include_lightning=True):
        print('wallet:Abstract_Wallet:get_full_history')
        transactions = OrderedDictWithIndex()
        onchain_history = self.get_onchain_history(domain=onchain_domain)
        for tx_item in onchain_history:
            txid = tx_item['txid']
            transactions[txid] = tx_item
        if self.lnworker and include_lightning:
            lightning_history = self.lnworker.get_history()
        else:
            lightning_history = []

        for i, tx_item in enumerate(lightning_history):
            txid = tx_item.get('txid')
            ln_value = Decimal(tx_item['amount_msat']) / 1000
            if txid and txid in transactions:
                item = transactions[txid]
                item['label'] = tx_item['label']
                item['ln_value'] = Satoshis(ln_value)
                item['ln_balance_msat'] = tx_item['balance_msat']
            else:
                tx_item['lightning'] = True
                tx_item['ln_value'] = Satoshis(ln_value)
                tx_item['txpos'] = i # for sorting
                key = tx_item['payment_hash'] if 'payment_hash' in tx_item else tx_item['type'] + tx_item['channel_id']
                transactions[key] = tx_item
        now = time.time()
        balance = 0
        for item in transactions.values():
            # add on-chain and lightning values
            value = Decimal(0)
            if item.get('bc_value'):
                value += item['bc_value'].value
            if item.get('ln_value'):
                value += item.get('ln_value').value
            item['value'] = Satoshis(value)
            balance += value
            item['balance'] = Satoshis(balance)
            if fx:
                timestamp = item['timestamp'] or now
                fiat_value = value / Decimal(bitcoin.COIN) * fx.timestamp_rate(timestamp)
                item['fiat_value'] = Fiat(fiat_value, fx.ccy)
                item['fiat_default'] = True
        return transactions

    @profiler
    def get_detailed_history(self, from_timestamp=None, to_timestamp=None,
                             fx=None, show_addresses=False):
        # History with capital gains, using utxo pricing
        # FIXME: Lightning capital gains would requires FIFO
        print('wallet:Abstract_Wallet:get_detailed_history')
        out = []
        income = 0
        expenditures = 0
        capital_gains = Decimal(0)
        fiat_income = Decimal(0)
        fiat_expenditures = Decimal(0)
        now = time.time()
        for item in self.get_onchain_history():
            timestamp = item['timestamp']
            if from_timestamp and (timestamp or now) < from_timestamp:
                continue
            if to_timestamp and (timestamp or now) >= to_timestamp:
                continue
            tx_hash = item['txid']
            tx = self.db.get_transaction(tx_hash)
            tx_fee = item['fee_sat']
            item['fee'] = Satoshis(tx_fee) if tx_fee is not None else None
            if show_addresses:
                item['inputs'] = list(map(lambda x: x.to_json(), tx.inputs()))
                item['outputs'] = list(map(lambda x: {'address': x.get_ui_address_str(), 'value': Satoshis(x.value)},
                                           tx.outputs()))
            # fixme: use in and out values
            value = item['bc_value'].value
            if value < 0:
                expenditures += -value
            else:
                income += value
            # fiat computations
            if fx and fx.is_enabled() and fx.get_history_config():
                fiat_fields = self.get_tx_item_fiat(tx_hash, value, fx, tx_fee)
                fiat_value = fiat_fields['fiat_value'].value
                item.update(fiat_fields)
                if value < 0:
                    capital_gains += fiat_fields['capital_gain'].value
                    fiat_expenditures += -fiat_value
                else:
                    fiat_income += fiat_value
            out.append(item)
        # add summary
        if out:
            b, v = out[0]['bc_balance'].value, out[0]['bc_value'].value
            start_balance = None if b is None or v is None else b - v
            end_balance = out[-1]['bc_balance'].value
            if from_timestamp is not None and to_timestamp is not None:
                start_date = timestamp_to_datetime(from_timestamp)
                end_date = timestamp_to_datetime(to_timestamp)
            else:
                start_date = None
                end_date = None
            summary = {
                'start_date': start_date,
                'end_date': end_date,
                'start_balance': Satoshis(start_balance),
                'end_balance': Satoshis(end_balance),
                'incoming': Satoshis(income),
                'outgoing': Satoshis(expenditures)
            }
            if fx and fx.is_enabled() and fx.get_history_config():
                unrealized = self.unrealized_gains(None, fx.timestamp_rate, fx.ccy)
                summary['fiat_currency'] = fx.ccy
                summary['fiat_capital_gains'] = Fiat(capital_gains, fx.ccy)
                summary['fiat_incoming'] = Fiat(fiat_income, fx.ccy)
                summary['fiat_outgoing'] = Fiat(fiat_expenditures, fx.ccy)
                summary['fiat_unrealized_gains'] = Fiat(unrealized, fx.ccy)
                summary['fiat_start_balance'] = Fiat(fx.historical_value(start_balance, start_date), fx.ccy)
                summary['fiat_end_balance'] = Fiat(fx.historical_value(end_balance, end_date), fx.ccy)
                summary['fiat_start_value'] = Fiat(fx.historical_value(COIN, start_date), fx.ccy)
                summary['fiat_end_value'] = Fiat(fx.historical_value(COIN, end_date), fx.ccy)
        else:
            summary = {}
        return {
            'transactions': out,
            'summary': summary
        }

    def default_fiat_value(self, tx_hash, fx, value_sat):
        return value_sat / Decimal(COIN) * self.price_at_timestamp(tx_hash, fx.timestamp_rate)

    def get_tx_item_fiat(self, tx_hash, value, fx, tx_fee):
        print('wallet:Abstract_Wallet:get_tx_item_fiat')
        item = {}
        fiat_value = self.get_fiat_value(tx_hash, fx.ccy)
        fiat_default = fiat_value is None
        fiat_rate = self.price_at_timestamp(tx_hash, fx.timestamp_rate)
        fiat_value = fiat_value if fiat_value is not None else self.default_fiat_value(tx_hash, fx, value)
        fiat_fee = tx_fee / Decimal(COIN) * fiat_rate if tx_fee is not None else None
        item['fiat_currency'] = fx.ccy
        item['fiat_rate'] = Fiat(fiat_rate, fx.ccy)
        item['fiat_value'] = Fiat(fiat_value, fx.ccy)
        item['fiat_fee'] = Fiat(fiat_fee, fx.ccy) if fiat_fee else None
        item['fiat_default'] = fiat_default
        if value < 0:
            acquisition_price = - value / Decimal(COIN) * self.average_price(tx_hash, fx.timestamp_rate, fx.ccy)
            liquidation_price = - fiat_value
            item['acquisition_price'] = Fiat(acquisition_price, fx.ccy)
            cg = liquidation_price - acquisition_price
            item['capital_gain'] = Fiat(cg, fx.ccy)
        return item

    def get_label(self, tx_hash: str) -> str:
        print('wallet:Abstract_Wallet:get_label')
        return self.labels.get(tx_hash, '') or self.get_default_label(tx_hash)

    def get_default_label(self, tx_hash) -> str:
        print('wallet:Abstract_Wallet:get_default_label')
        if not self.db.get_txi_addresses(tx_hash):
            labels = []
            for addr in self.db.get_txo_addresses(tx_hash):
                label = self.labels.get(addr)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, tx_mined_info: TxMinedInfo):
        print('wallet:Abstract_Wallet:get_tx_status')
        extra = []
        height = tx_mined_info.height
        conf = tx_mined_info.conf
        timestamp = tx_mined_info.timestamp
        if height == TX_HEIGHT_FUTURE:
            assert conf < 0, conf
            num_blocks_remainining = -conf
            return 2, f'in {num_blocks_remainining} blocks'
        if conf == 0:
            tx = self.db.get_transaction(tx_hash)
            if not tx:
                return 2, 'unknown'
            is_final = tx and tx.is_final()
            if not is_final:
                extra.append('rbf')
            fee = self.get_tx_fee(tx_hash)
            if fee is not None:
                size = tx.estimated_size()
                fee_per_byte = fee / size
                extra.append(format_fee_satoshis(fee_per_byte) + ' sat/b')
            if fee is not None and height in (TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED) \
               and self.config.has_fee_mempool():
                exp_n = self.config.fee_to_depth(fee_per_byte)
                if exp_n:
                    extra.append('%.2f MB'%(exp_n/1000000))
            if height == TX_HEIGHT_LOCAL:
                status = 3
            elif height == TX_HEIGHT_UNCONF_PARENT:
                status = 1
            elif height == TX_HEIGHT_UNCONFIRMED:
                status = 0
            else:
                status = 2  # not SPV verified
        else:
            status = 3 + min(conf, 6)
        time_str = format_time(timestamp) if timestamp else _("unknown")
        status_str = TX_STATUS[status] if status < 4 else time_str
        if extra:
            status_str += ' [%s]'%(', '.join(extra))
        return status, status_str

    def relayfee(self):
        return relayfee(self.network)

    def dust_threshold(self):
        return dust_threshold(self.network)

    def get_unconfirmed_base_tx_for_batching(self) -> Optional[Transaction]:
        print('wallet:Abstract_Wallet:get_unconfirmed_base_tx_for_batching')
        candidate = None
        for hist_item in self.get_history():
            # tx should not be mined yet
            if hist_item.tx_mined_status.conf > 0: continue
            # conservative future proofing of code: only allow known unconfirmed types
            if hist_item.tx_mined_status.height not in (TX_HEIGHT_UNCONFIRMED,
                                                        TX_HEIGHT_UNCONF_PARENT,
                                                        TX_HEIGHT_LOCAL):
                continue
            # tx should be "outgoing" from wallet
            if hist_item.delta >= 0:
                continue
            tx = self.db.get_transaction(hist_item.txid)
            if not tx:
                continue
            # is_mine outputs should not be spent yet
            # to avoid cancelling our own dependent transactions
            txid = tx.txid()
            if any([self.is_mine(o.address) and self.db.get_spent_outpoint(txid, output_idx)
                    for output_idx, o in enumerate(tx.outputs())]):
                continue
            # all inputs should be is_mine
            if not all([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()]):
                continue
            # prefer txns already in mempool (vs local)
            if hist_item.tx_mined_status.height == TX_HEIGHT_LOCAL:
                candidate = tx
                continue
            # tx must have opted-in for RBF
            if tx.is_final(): continue
            return tx
        return candidate

    def get_change_addresses_for_new_transaction(self, preferred_change_addr=None) -> List[str]:
        print('wallet:Abstract_Wallet:get_change_address_for_new_transaction')
        change_addrs = []
        if preferred_change_addr:
            if isinstance(preferred_change_addr, (list, tuple)):
                change_addrs = list(preferred_change_addr)
            else:
                change_addrs = [preferred_change_addr]
        elif self.use_change:
            # Recalc and get unused change addresses
            addrs = self.calc_unused_change_addresses()
            # New change addresses are created only after a few
            # confirmations.
            if addrs:
                # if there are any unused, select all
                change_addrs = addrs
            else:
                # if there are none, take one randomly from the last few
                addrs = self.get_change_addresses(slice_start=-self.gap_limit_for_change)
                change_addrs = [random.choice(addrs)] if addrs else []
        for addr in change_addrs:
            assert is_address(addr), f"not valid bitcoin address: {addr}"
            # note that change addresses are not necessarily ismine
            # in which case this is a no-op
            self.check_address(addr)
        max_change = self.max_change_outputs if self.multiple_change else 1
        return change_addrs[:max_change]

    def make_unsigned_transaction(self, *, coins: Sequence[PartialTxInput],
                                  outputs: List[PartialTxOutput], fee=None,
                                  change_addr: str = None, is_sweep=False) -> PartialTransaction:
        print('wallet:Abstract_Wallet:make_unsigned_transaction coins={} outputs={}'.format([coin.to_json() for coin in coins], [output.to_json() for output in outputs]))
        print('wallet:Abstract_Wallet:make_unsigned_transaction keystore={}'.format(self.keystore.to_json()))

        # prevent side-effect with '!'
        outputs = copy.deepcopy(outputs)

        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            if o.value == '!':
                if i_max is not None:
                    raise Exception("More than one output set to spend max")
                i_max = i

        if fee is None and self.config.fee_per_kb() is None:
            raise NoDynamicFeeEstimates()

        for item in coins:
            self.add_input_info(item)

        # Fee estimator
        if fee is None:
            fee_estimator = self.config.estimate_fee
        elif isinstance(fee, Number):
            fee_estimator = lambda size: fee
        elif callable(fee):
            fee_estimator = fee
        else:
            raise Exception(f'Invalid argument fee: {fee}')

        if i_max is None:
            # Let the coin chooser select the coins to spend
            coin_chooser = coinchooser.get_coin_chooser(self.config)
            # If there is an unconfirmed RBF tx, merge with it
            base_tx = self.get_unconfirmed_base_tx_for_batching()
            if self.config.get('batch_rbf', False) and base_tx:
                # make sure we don't try to spend change from the tx-to-be-replaced:
                coins = [c for c in coins if c.prevout.txid.hex() != base_tx.txid()]
                is_local = self.get_tx_height(base_tx.txid()).height == TX_HEIGHT_LOCAL
                base_tx = PartialTransaction.from_tx(base_tx)
                print('make_unsigned_transaction: base_tx={}'.format(base_tx.to_json()))
                base_tx.add_info_from_wallet(self)
                print('make_unsigned_transaction: base_tx={}'.format(base_tx.to_json()))
                base_tx_fee = base_tx.get_fee()
                relayfeerate = Decimal(self.relayfee()) / 1000
                original_fee_estimator = fee_estimator
                def fee_estimator(size: Union[int, float, Decimal]) -> int:
                    size = Decimal(size)
                    lower_bound = base_tx_fee + round(size * relayfeerate)
                    lower_bound = lower_bound if not is_local else 0
                    return int(max(lower_bound, original_fee_estimator(size)))
                txi = base_tx.inputs()
                txo = list(filter(lambda o: not self.is_change(o.address), base_tx.outputs()))
                old_change_addrs = [o.address for o in base_tx.outputs() if self.is_change(o.address)]
            else:
                txi = []
                txo = []
                old_change_addrs = []
            # change address. if empty, coin_chooser will set it
            change_addrs = self.get_change_addresses_for_new_transaction(change_addr or old_change_addrs)
            print('make_unsigned_transaction: txi={}'.format([input.address for input in txi]))
            tx = coin_chooser.make_tx(coins=coins,
                                      inputs=txi,
                                      outputs=list(outputs) + txo,
                                      change_addrs=change_addrs,
                                      fee_estimator_vb=fee_estimator,
                                      dust_threshold=self.dust_threshold())
        else:
            # "spend max" branch
            # note: This *will* spend inputs with negative effective value (if there are any).
            #       Given as the user is spending "max", and so might be abandoning the wallet,
            #       try to include all UTXOs, otherwise leftover might remain in the UTXO set
            #       forever. see #5433
            # note: Actually it might be the case that not all UTXOs from the wallet are
            #       being spent if the user manually selected UTXOs.
            sendable = sum(map(lambda c: c.value_sats(), coins))
            outputs[i_max].value = 0
            tx = PartialTransaction.from_io(list(coins), list(outputs))
            fee = fee_estimator(tx.estimated_size())
            amount = sendable - tx.output_value() - fee
            if amount < 0:
                raise NotEnoughFunds()
            outputs[i_max].value = amount
            tx = PartialTransaction.from_io(list(coins), list(outputs))

        # Timelock tx to current height.
        tx.locktime = get_locktime_for_new_transaction(self.network)

        print('make_unsigned_transaction: base_tx={}'.format(tx.to_json()))
        tx.add_info_from_wallet(self)
        run_hook('make_unsigned_transaction', self, tx)
        print('wallet:Abstract_Wallet:make_unsigned_transaction tx={}'.format(tx.to_json()))
        print('***wallet:Abstract_Wallet:make_unsigned_transaction addresses={}'.format([input.address for input in tx.inputs()]))
        return tx

    def mktx(self, *, outputs: List[PartialTxOutput], password=None, fee=None, change_addr=None,
             domain=None, rbf=False, nonlocal_only=False, tx_version=None, sign=True) -> PartialTransaction:
        print('wallet:Abstract_Wallet:mktx')
        coins = self.get_spendable_coins(domain, nonlocal_only=nonlocal_only)
        tx = self.make_unsigned_transaction(coins=coins,
                                            outputs=outputs,
                                            fee=fee,
                                            change_addr=change_addr)
        tx.set_rbf(rbf)
        if tx_version is not None:
            tx.version = tx_version
        if sign:
            self.sign_transaction(tx, password)
        return tx

    def is_frozen_address(self, addr: str) -> bool:
        print('wallet:Abstract_Wallet:is_frozen_address')
        return addr in self.frozen_addresses

    def is_frozen_coin(self, utxo: PartialTxInput) -> bool:
        print('wallet:Abstract_Wallet:is_frozen_coin')
        prevout_str = utxo.prevout.to_str()
        return prevout_str in self.frozen_coins

    def set_frozen_state_of_addresses(self, addrs, freeze: bool):
        """Set frozen state of the addresses to FREEZE, True or False"""
        print('wallet:Abstract_Wallet:set_frozen_state_of_addresses')
        if all(self.is_mine(addr) for addr in addrs):
            # FIXME take lock?
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            self.storage.put('frozen_addresses', list(self.frozen_addresses))
            return True
        return False

    def set_frozen_state_of_coins(self, utxos: Sequence[PartialTxInput], freeze: bool):
        """Set frozen state of the utxos to FREEZE, True or False"""
        print('wallet:Abstract_Wallet:set_frozen_state_of_coins')
        utxos = {utxo.prevout.to_str() for utxo in utxos}
        # FIXME take lock?
        if freeze:
            self.frozen_coins |= set(utxos)
        else:
            self.frozen_coins -= set(utxos)
        self.storage.put('frozen_coins', list(self.frozen_coins))

    def wait_until_synchronized(self, callback=None):
        print('wallet:Abstract_Wallet:wait_until_synchronized')
        def wait_for_wallet():
            self.set_up_to_date(False)
            while not self.is_up_to_date():
                if callback:
                    msg = "{}\n{} {}".format(
                        _("Please wait..."),
                        _("Addresses generated:"),
                        len(self.get_addresses()))
                    callback(msg)
                time.sleep(0.1)
        def wait_for_network():
            while not self.network.is_connected():
                if callback:
                    msg = "{} \n".format(_("Connecting..."))
                    callback(msg)
                time.sleep(0.1)
        # wait until we are connected, because the user
        # might have selected another server
        if self.network:
            self.logger.info("waiting for network...")
            wait_for_network()
            self.logger.info("waiting while wallet is syncing...")
            wait_for_wallet()
        else:
            self.synchronize()

    def can_export(self):
        print('wallet:Abstract_Wallet:can_export')
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def address_is_old(self, address: str, *, req_conf: int = 3) -> bool:
        """Returns whether address has any history that is deeply confirmed."""
        #print('wallet:Abstract_Wallet:address_is_old')
        max_conf = -1
        h = self.db.get_addr_history(address)
        needs_spv_check = not self.config.get("skipmerklecheck", False)
        for tx_hash, tx_height in h:
            if needs_spv_check:
                tx_age = self.get_tx_height(tx_hash).conf
            else:
                if tx_height <= 0:
                    tx_age = 0
                else:
                    tx_age = self.get_local_height() - tx_height + 1
            max_conf = max(max_conf, tx_age)
        return max_conf >= req_conf

    def bump_fee(self, *, tx: Transaction, new_fee_rate: Union[int, float, Decimal],
                 coins: Sequence[PartialTxInput] = None) -> PartialTransaction:
        """Increase the miner fee of 'tx'.
        'new_fee_rate' is the target min rate in sat/vbyte
        'coins' is a list of UTXOs we can choose from as potential new inputs to be added
        """
        print('wallet:Abstract_Wallet:bump_fee tx={} new_fee_rate={}'.format(tx, new_fee_rate))
        if tx.is_final():
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('transaction is final'))
        new_fee_rate = quantize_feerate(new_fee_rate)  # strip excess precision
        old_tx_size = tx.estimated_size()
        old_txid = tx.txid()
        assert old_txid
        old_fee = self.get_tx_fee(old_txid)
        if old_fee is None:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('current fee unknown'))
        old_fee_rate = old_fee / old_tx_size  # sat/vbyte
        if new_fee_rate <= old_fee_rate:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _("The new fee rate needs to be higher than the old fee rate."))

        try:
            # method 1: keep all inputs, keep all not is_mine outputs,
            #           allow adding new inputs
            tx_new = self._bump_fee_through_coinchooser(
                tx=tx, new_fee_rate=new_fee_rate, coins=coins)
            method_used = 1
        except CannotBumpFee:
            # method 2: keep all inputs, no new inputs are added,
            #           allow decreasing and removing outputs (change is decreased first)
            # This is less "safe" as it might end up decreasing e.g. a payment to a merchant;
            # but e.g. if the user has sent "Max" previously, this is the only way to RBF.
            tx_new = self._bump_fee_through_decreasing_outputs(
                tx=tx, new_fee_rate=new_fee_rate)
            method_used = 2

        target_min_fee = new_fee_rate * tx_new.estimated_size()
        actual_fee = tx_new.get_fee()
        if actual_fee + 1 < target_min_fee:
            raise Exception(f"bump_fee fee target was not met (method: {method_used}). "
                            f"got {actual_fee}, expected >={target_min_fee}. "
                            f"target rate was {new_fee_rate}")

        tx_new.locktime = get_locktime_for_new_transaction(self.network)
        return tx_new

    def _bump_fee_through_coinchooser(self, *, tx: Transaction, new_fee_rate: Union[int, Decimal],
                                      coins: Sequence[PartialTxInput] = None) -> PartialTransaction:
        print('wallet:Abstract_Wallet:_bump_fee_through_coinchooser tx={} new_fee_rate={}'.format(tx, new_fee_rate))
        tx = PartialTransaction.from_tx(tx)
        tx.add_info_from_wallet(self)
        old_inputs = list(tx.inputs())
        old_outputs = list(tx.outputs())
        # change address
        old_change_addrs = [o.address for o in old_outputs if self.is_change(o.address)]
        change_addrs = self.get_change_addresses_for_new_transaction(old_change_addrs)
        # which outputs to keep?
        if old_change_addrs:
            fixed_outputs = list(filter(lambda o: not self.is_change(o.address), old_outputs))
        else:
            if all(self.is_mine(o.address) for o in old_outputs):
                # all outputs are is_mine and none of them are change.
                # we bail out as it's unclear what the user would want!
                # the coinchooser bump fee method is probably not a good idea in this case
                raise CannotBumpFee(_('Cannot bump fee') + ': all outputs are non-change is_mine')
            old_not_is_mine = list(filter(lambda o: not self.is_mine(o.address), old_outputs))
            if old_not_is_mine:
                fixed_outputs = old_not_is_mine
            else:
                fixed_outputs = old_outputs
        if not fixed_outputs:
            raise CannotBumpFee(_('Cannot bump fee') + ': could not figure out which outputs to keep')

        if coins is None:
            coins = self.get_spendable_coins(None)
        # make sure we don't try to spend output from the tx-to-be-replaced:
        coins = [c for c in coins if c.prevout.txid.hex() != tx.txid()]
        for item in coins:
            self.add_input_info(item)
        def fee_estimator(size):
            return self.config.estimate_fee_for_feerate(fee_per_kb=new_fee_rate*1000, size=size)
        coin_chooser = coinchooser.get_coin_chooser(self.config)
        try:
            return coin_chooser.make_tx(coins=coins,
                                        inputs=old_inputs,
                                        outputs=fixed_outputs,
                                        change_addrs=change_addrs,
                                        fee_estimator_vb=fee_estimator,
                                        dust_threshold=self.dust_threshold())
        except NotEnoughFunds as e:
            raise CannotBumpFee(e)

    def _bump_fee_through_decreasing_outputs(self, *, tx: Transaction,
                                             new_fee_rate: Union[int, Decimal]) -> PartialTransaction:
        print('wallet:Abstract_Wallet:_bump_fee_through_decreasing_outputs tx={} new_fee_rate={}'.format(tx, new_fee_rate))
        tx = PartialTransaction.from_tx(tx)
        tx.add_info_from_wallet(self)
        inputs = tx.inputs()
        outputs = list(tx.outputs())

        # use own outputs
        s = list(filter(lambda o: self.is_mine(o.address), outputs))
        # ... unless there is none
        if not s:
            s = outputs
            x_fee = run_hook('get_tx_extra_fee', self, tx)
            if x_fee:
                x_fee_address, x_fee_amount = x_fee
                s = filter(lambda o: o.address != x_fee_address, s)
        if not s:
            raise CannotBumpFee(_('Cannot bump fee') + ': no outputs at all??')

        # prioritize low value outputs, to get rid of dust
        s = sorted(s, key=lambda o: o.value)
        for o in s:
            target_fee = int(round(tx.estimated_size() * new_fee_rate))
            delta = target_fee - tx.get_fee()
            i = outputs.index(o)
            if o.value - delta >= self.dust_threshold():
                new_output_value = o.value - delta
                assert isinstance(new_output_value, int)
                outputs[i].value = new_output_value
                delta = 0
                break
            else:
                del outputs[i]
                delta -= o.value
                # note: delta might be negative now, in which case
                # the value of the next output will be increased
        if delta > 0:
            raise CannotBumpFee(_('Cannot bump fee') + ': ' + _('could not find suitable outputs'))

        return PartialTransaction.from_io(inputs, outputs)

    def cpfp(self, tx: Transaction, fee: int) -> Optional[PartialTransaction]:
        print('wallet:Abstract_Wallet:cpfp tx={} fee={}'.format(tx, fee))
        txid = tx.txid()
        for i, o in enumerate(tx.outputs()):
            address, value = o.address, o.value
            if self.is_mine(address):
                break
        else:
            return
        coins = self.get_addr_utxo(address)
        item = coins.get(TxOutpoint.from_str(txid+':%d'%i))
        if not item:
            return
        self.add_input_info(item)
        inputs = [item]
        out_address = self.get_unused_address() or address
        outputs = [PartialTxOutput.from_address_and_value(out_address, value - fee)]
        locktime = get_locktime_for_new_transaction(self.network)
        return PartialTransaction.from_io(inputs, outputs, locktime=locktime)

    def _add_input_sig_info(self, txin: PartialTxInput, address: str, *, only_der_suffix: bool = True) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def _add_txinout_derivation_info(self, txinout: Union[PartialTxInput, PartialTxOutput],
                                     address: str, *, only_der_suffix: bool = True) -> None:
        pass  # implemented by subclasses

    def _add_input_utxo_info(self, txin: PartialTxInput, address: str) -> None:
        if Transaction.is_segwit_input(txin):
            if txin.witness_utxo is None:
                received, spent = self.get_addr_io(address)
                item = received.get(txin.prevout.to_str())
                if item:
                    txin_value = item[1]
                    txin.witness_utxo = TxOutput.from_address_and_value(address, txin_value)
        else:  # legacy input
            if txin.utxo is None:
                # note: for hw wallets, for legacy inputs, ignore_network_issues used to be False
                txin.utxo = self.get_input_tx(txin.prevout.txid.hex(), ignore_network_issues=True)
        # If there is a NON-WITNESS UTXO, but we know input is segwit, add a WITNESS UTXO, based on it.
        # This could have happened if previously another wallet had put a NON-WITNESS UTXO for txin,
        # as they did not know if it was segwit. This switch is needed to interop with bitcoin core.
        if txin.utxo and Transaction.is_segwit_input(txin):
            txin.convert_utxo_to_witness_utxo()
        txin.ensure_there_is_only_one_utxo()

    def _learn_derivation_path_for_address_from_txinout(self, txinout: Union[PartialTxInput, PartialTxOutput],
                                                        address: str) -> bool:
        """Tries to learn the derivation path for an address (potentially beyond gap limit)
        using data available in given txin/txout.
        Returns whether the address was found to be is_mine.
        """
        return False  # implemented by subclasses

    def add_input_info(self, txin: PartialTxInput, *, only_der_suffix: bool = True) -> None:
        address = self.get_txin_address(txin)
        print('***wallet:Abstract_Wallet:add_input_info address={} txin={}'.format(address, txin.to_json()))
        if not self.is_mine(address):
            is_mine = self._learn_derivation_path_for_address_from_txinout(txin, address)
            if not is_mine:
                return
        # set script_type first, as later checks might rely on it:
        txin.script_type = self.get_txin_type(address)
        self._add_input_utxo_info(txin, address)
        txin.num_sig = self.m if isinstance(self, Multisig_Wallet) else 1
        if txin.redeem_script is None:
            try:
                redeem_script_hex = self.get_redeem_script(address)
                txin.redeem_script = bfh(redeem_script_hex) if redeem_script_hex else None
            except UnknownTxinType:
                pass
        if txin.witness_script is None:
            try:
                witness_script_hex = self.get_witness_script(address)
                txin.witness_script = bfh(witness_script_hex) if witness_script_hex else None
            except UnknownTxinType:
                pass
        print('wallet:Abstract_Wallet:add_input_info calling _add_input_sig_info')
        self._add_input_sig_info(txin, address, only_der_suffix=only_der_suffix)

    def can_sign(self, tx: Transaction) -> bool:
        print('wallet:Abstract_Wallet:can_sign')
        if not isinstance(tx, PartialTransaction):
            print('wallet:Abstract_Wallet:can_sign False (not a partialtransaction)')
            return False
        if tx.is_complete():
            print('wallet:Abstract_Wallet:can_sign False (is_compelte)')
            return False
        # add info to inputs if we can; otherwise we might return a false negative:
        tx.add_info_from_wallet(self)
        for k in self.get_keystores():
            if k.can_sign(tx):
                print('wallet:Abstract_Wallet:can_sign False (found)')
                return True
        print('wallet:Abstract_Wallet:can_sign False (not found)')
        return False

    def get_input_tx(self, tx_hash, *, ignore_network_issues=False) -> Optional[Transaction]:
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        print('wallet:Abstract_Wallet:get_input_tx')
        tx = self.db.get_transaction(tx_hash)
        if not tx and self.network:
            try:
                raw_tx = self.network.run_from_another_thread(
                    self.network.get_transaction(tx_hash, timeout=10))
            except NetworkException as e:
                self.logger.info(f'got network error getting input txn. err: {repr(e)}. txid: {tx_hash}. '
                                 f'if you are intentionally offline, consider using the --offline flag')
                if not ignore_network_issues:
                    raise e
            else:
                tx = Transaction(raw_tx)
        return tx

    def add_output_info(self, txout: PartialTxOutput, *, only_der_suffix: bool = True) -> None:
        print('***wallet:Abstract_Wallet:add_output_info')
        address = txout.address
        if not self.is_mine(address):
            is_mine = self._learn_derivation_path_for_address_from_txinout(txout, address)
            if not is_mine:
                return
        txout.script_type = self.get_txin_type(address)
        txout.is_mine = True
        txout.is_change = self.is_change(address)
        if isinstance(self, Multisig_Wallet):
            txout.num_sig = self.m
        self._add_txinout_derivation_info(txout, address, only_der_suffix=only_der_suffix)
        if txout.redeem_script is None:
            try:
                redeem_script_hex = self.get_redeem_script(address)
                txout.redeem_script = bfh(redeem_script_hex) if redeem_script_hex else None
            except UnknownTxinType:
                pass
        if txout.witness_script is None:
            try:
                witness_script_hex = self.get_witness_script(address)
                txout.witness_script = bfh(witness_script_hex) if witness_script_hex else None
            except UnknownTxinType:
                pass

    def sign_transaction(self, tx: Transaction, password, sync=True) -> Optional[PartialTransaction]:
        print('$$$wallet:Abstract_Wallet:sign_transaction tx={}'.format(tx.to_json()))
        if self.is_watching_only():
            return
        if not isinstance(tx, PartialTransaction):
            return
        # add info to a temporary tx copy; including xpubs
        # and full derivation paths as hw keystores might want them
        tmp_tx = copy.deepcopy(tx)
        tmp_tx.add_info_from_wallet(self, include_xpubs_and_full_paths=True)
        # sign. start with ready keystores.
        for k in sorted(self.get_keystores(), key=lambda ks: ks.ready_to_sign(), reverse=True):
            try:
                if k.can_sign(tmp_tx):
                    k.sign_transaction(tmp_tx, password, sync)
            except UserCancelled:
                continue
        # remove sensitive info; then copy back details from temporary tx
        tmp_tx.remove_xpubs_and_bip32_paths()
        tx.combine_with_other_psbt(tmp_tx)
        tx.add_info_from_wallet(self, include_xpubs_and_full_paths=False)
        print('$$$wallet:Abstract_Wallet:sign_transaction signed tx={}'.format(tx.to_json()))
        print('$$$wallet:Abstract_Wallet:sign_transaction signed tx={}'.format(tx))
        return tx

    def get_signed_transaction(self, tx: Transaction, password) -> Optional[PartialTransaction]:
        raise NotImplementedError()  # implemented by subclasses

    def try_detecting_internal_addresses_corruption(self):
        pass

    def check_address(self, addr):
        pass

    def check_returned_address(func):
        print('wallet:Abstract_Wallet:check_returned_address')
        def wrapper(self, *args, **kwargs):
            addr = func(self, *args, **kwargs)
            self.check_address(addr)
            return addr
        return wrapper

    def get_unused_addresses(self):
        domain = self.get_receiving_addresses()
        in_use = [k for k in self.receive_requests.keys() if self.get_request_status(k)[0] != PR_EXPIRED]
        #return [addr for addr in domain if not self.db.get_addr_history(addr)
        #       and addr not in in_use]
        addresses= [addr for addr in domain if not self.db.get_addr_history(addr)
                    and addr not in in_use]
        print('get_unused_addresses: {}'.format(' '.join(addresses)))
        return addresses

    @check_returned_address
    def get_unused_address(self):
        print('wallet:Abstract_Wallet:get_unused_address')
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    @check_returned_address
    def get_receiving_address(self):
        # always return an address
        print('wallet:Abstract_Wallet:get_receiving_address')
        domain = self.get_receiving_addresses()
        if not domain:
            return
        choice = domain[0]
        for addr in domain:
            if not self.db.get_addr_history(addr):
                if addr not in self.receive_requests.keys():
                    return addr
                else:
                    choice = addr
        return choice

    def create_new_address(self, for_change=False):
        raise Exception("this wallet cannot generate new addresses")

    def get_payment_status(self, address, amount):
        print('wallet:Abstract_Wallet:get_payment_status')
        local_height = self.get_local_height()
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb = x
            txid, n = txo.split(':')
            info = self.db.get_verified_tx(txid)
            if info:
                conf = local_height - info.height + 1
            else:
                conf = 0
            l.append((conf, v))
        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= amount:
                return True, conf
        return False, None

    def get_request_URI(self, addr):
        print('wallet:Abstract_Wallet:get_request_URI')
        req = self.receive_requests[addr]
        message = self.labels.get(addr, '')
        amount = req['amount']
        extra_query_params = {}
        if req.get('time'):
            extra_query_params['time'] = str(int(req.get('time')))
        if req.get('exp'):
            extra_query_params['exp'] = str(int(req.get('exp')))
        if req.get('name') and req.get('sig'):
            sig = bfh(req.get('sig'))
            sig = bitcoin.base_encode(sig, base=58)
            extra_query_params['name'] = req['name']
            extra_query_params['sig'] = sig
        uri = create_bip21_uri(addr, amount, message, extra_query_params=extra_query_params)
        return str(uri)

    def get_request_status(self, address):
        print('wallet:Abstract_Wallet:get_request_status')
        r = self.receive_requests.get(address)
        if r is None:
            return PR_UNKNOWN
        amount = r.get('amount', 0) or 0
        timestamp = r.get('time', 0)
        if timestamp and type(timestamp) != int:
            timestamp = 0
        expiration = r.get('exp')
        if expiration and type(expiration) != int:
            expiration = 0
        paid, conf = self.get_payment_status(address, amount)
        if not paid:
            if expiration is not None and time.time() > timestamp + expiration:
                status = PR_EXPIRED
            else:
                status = PR_UNPAID
        else:
            status = PR_PAID
        return status, conf

    def get_request(self, key):
        print('wallet:Abstract_Wallet:get_request')
        req = self.receive_requests.get(key)
        if not req:
            return
        req = copy.copy(req)
        _type = req.get('type')
        if _type == PR_TYPE_ONCHAIN:
            addr = req['address']
            req['URI'] = self.get_request_URI(addr)
            status, conf = self.get_request_status(addr)
            req['status'] = status
            if conf is not None:
                req['confirmations'] = conf
        elif self.lnworker and _type == PR_TYPE_LN:
            req['status'] = self.lnworker.get_payment_status(bfh(key))
        else:
            return
        # add URL if we are running a payserver
        if self.config.get('run_payserver'):
            host = self.config.get('payserver_host', 'localhost')
            port = self.config.get('payserver_port', 8002)
            root = self.config.get('payserver_root', '/r')
            use_ssl = bool(self.config.get('ssl_keyfile'))
            protocol = 'https' if use_ssl else 'http'
            base = '%s://%s:%d'%(protocol, host, port)
            req['view_url'] = base + root + '/pay?id=' + key
            if use_ssl and 'URI' in req:
                request_url = base + '/bip70/' + key + '.bip70'
                req['bip70_url'] = request_url
        return req

    def receive_tx_callback(self, tx_hash, tx, tx_height):
        print('wallet:Abstract_Wallet:receive_tx_callback')
        super().receive_tx_callback(tx_hash, tx, tx_height)
        for txo in tx.outputs():
            addr = self.get_txout_address(txo)
            if addr in self.receive_requests:
                status, conf = self.get_request_status(addr)
                self.network.trigger_callback('payment_received', self, addr, status)

    def make_payment_request(self, addr, amount, message, expiration):
        print('wallet:Abstract_Wallet:make_payment_request')
        timestamp = int(time.time())
        _id = bh2u(sha256d(addr + "%d"%timestamp))[0:10]
        return {
            'type': PR_TYPE_ONCHAIN,
            'time':timestamp,
            'amount':amount,
            'exp':expiration,
            'address':addr,
            'memo':message,
            'id':_id,
            'outputs': [PartialTxOutput.from_address_and_value(addr, amount)],
        }

    def sign_payment_request(self, key, alias, alias_addr, password):
        print('wallet:Abstract_Wallet:sign_payment_request')
        req = self.receive_requests.get(key)
        alias_privkey = self.export_private_key(alias_addr, password)
        pr = paymentrequest.make_unsigned_request(req)
        paymentrequest.sign_request_with_alias(pr, alias, alias_privkey)
        req['name'] = pr.pki_data
        req['sig'] = bh2u(pr.signature)
        self.receive_requests[key] = req
        self.storage.put('payment_requests', self.receive_requests)

    def add_payment_request(self, req):
        print('wallet:Abstract_Wallet:add_payment_request')
        if req['type'] == PR_TYPE_ONCHAIN:
            addr = req['address']
            if not bitcoin.is_address(addr):
                raise Exception(_('Invalid Bitcoin address.'))
            if not self.is_mine(addr):
                raise Exception(_('Address not in wallet.'))
            key = addr
            message = req['memo']
        elif req['type'] == PR_TYPE_LN:
            key = req['rhash']
            message = req['message']
        else:
            raise Exception('Unknown request type')
        amount = req.get('amount')
        self.receive_requests[key] = req
        self.storage.put('payment_requests', self.receive_requests)
        self.set_label(key, message) # should be a default label
        return req

    def delete_request(self, key):
        """ lightning or on-chain """
        print('wallet:Abstract_Wallet:delete_request')
        if key in self.receive_requests:
            self.remove_payment_request(key)
        elif self.lnworker:
            self.lnworker.delete_payment(key)

    def delete_invoice(self, key):
        """ lightning or on-chain """
        print('wallet:Abstract_Wallet:delete_invoice')
        if key in self.invoices:
            self.invoices.pop(key)
            self.storage.put('invoices', self.invoices)
        elif self.lnworker:
            self.lnworker.delete_payment(key)

    def remove_payment_request(self, addr):
        print('wallet:Abstract_Wallet:remove_payment_request')
        if addr not in self.receive_requests:
            return False
        self.receive_requests.pop(addr)
        self.storage.put('payment_requests', self.receive_requests)
        return True

    def get_sorted_requests(self):
        """ sorted by timestamp """
        print('wallet:Abstract_Wallet:get_sorted_requests')
        out = [self.get_request(x) for x in self.receive_requests.keys()]
        out = [x for x in out if x is not None]
        out.sort(key=operator.itemgetter('time'))
        return out

    def get_fingerprint(self):
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def has_password(self):
        return self.has_keystore_encryption() or self.has_storage_encryption()

    def can_have_keystore_encryption(self):
        return self.keystore and self.keystore.may_have_password()

    def get_available_storage_encryption_version(self) -> StorageEncryptionVersion:
        """Returns the type of storage encryption offered to the user.

        A wallet file (storage) is either encrypted with this version
        or is stored in plaintext.
        """
        if isinstance(self.keystore, Hardware_KeyStore):
            return StorageEncryptionVersion.XPUB_PASSWORD
        else:
            return StorageEncryptionVersion.USER_PASSWORD

    def has_keystore_encryption(self):
        """Returns whether encryption is enabled for the keystore.

        If True, e.g. signing a transaction will require a password.
        """
        if self.can_have_keystore_encryption():
            return self.storage.get('use_encryption', False)
        return False

    def has_storage_encryption(self):
        """Returns whether encryption is enabled for the wallet file on disk."""
        return self.storage.is_encrypted()

    @classmethod
    def may_have_password(cls):
        return True

    def check_password(self, password):
        if self.has_keystore_encryption():
            self.keystore.check_password(password)
        self.storage.check_password(password)

    def update_password(self, old_pw, new_pw, encrypt_storage=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        self.check_password(old_pw)

        if encrypt_storage:
            enc_version = self.get_available_storage_encryption_version()
        else:
            enc_version = StorageEncryptionVersion.PLAINTEXT
        self.storage.set_password(new_pw, enc_version)

        # note: Encrypting storage with a hw device is currently only
        #       allowed for non-multisig wallets. Further,
        #       Hardware_KeyStore.may_have_password() == False.
        #       If these were not the case,
        #       extra care would need to be taken when encrypting keystores.
        self._update_password_for_keystore(old_pw, new_pw)
        encrypt_keystore = self.can_have_keystore_encryption()
        self.storage.set_keystore_encryption(bool(new_pw) and encrypt_keystore)
        self.storage.write()

    def sign_message(self, address, message, password):
        print('wallet:Abstract_Wallet:sign_message')
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password) -> bytes:
        print('wallet:Abstract_Wallet:decrypt_message')
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)

    def txin_value(self, txin: TxInput) -> Optional[int]:
        print('wallet:Abstract_Wallet:txin_value')
        if isinstance(txin, PartialTxInput):
            v = txin.value_sats()
            if v: return v
        txid = txin.prevout.txid.hex()
        prev_n = txin.prevout.out_idx
        for addr in self.db.get_txo_addresses(txid):
            d = self.db.get_txo_addr(txid, addr)
            for n, v, cb in d:
                if n == prev_n:
                    return v
        # may occur if wallet is not synchronized
        return None

    def price_at_timestamp(self, txid, price_func):
        """Returns fiat price of bitcoin at the time tx got confirmed."""
        print('wallet:Abstract_Wallet:price_at_timestatmp')
        timestamp = self.get_tx_height(txid).timestamp
        return price_func(timestamp if timestamp else time.time())

    def unrealized_gains(self, domain, price_func, ccy):
        print('wallet:Abstract_Wallet:unrelaized_gains')
        coins = self.get_utxos(domain)
        now = time.time()
        p = price_func(now)
        ap = sum(self.coin_price(coin.prevout.txid.hex(), price_func, ccy, self.txin_value(coin)) for coin in coins)
        lp = sum([coin.value_sats() for coin in coins]) * p / Decimal(COIN)
        return lp - ap

    def average_price(self, txid, price_func, ccy):
        """ Average acquisition price of the inputs of a transaction """
        print('wallet:Abstract_Wallet:average_price')
        input_value = 0
        total_price = 0
        for addr in self.db.get_txi_addresses(txid):
            d = self.db.get_txi_addr(txid, addr)
            for ser, v in d:
                input_value += v
                total_price += self.coin_price(ser.split(':')[0], price_func, ccy, v)
        return total_price / (input_value/Decimal(COIN))

    def clear_coin_price_cache(self):
        self._coin_price_cache = {}

    def coin_price(self, txid, price_func, ccy, txin_value):
        """
        Acquisition price of a coin.
        This assumes that either all inputs are mine, or no input is mine.
        """
        print('wallet:Abstract_Wallet:coin_price')
        if txin_value is None:
            return Decimal('NaN')
        cache_key = "{}:{}:{}".format(str(txid), str(ccy), str(txin_value))
        result = self._coin_price_cache.get(cache_key, None)
        if result is not None:
            return result
        if self.db.get_txi_addresses(txid):
            result = self.average_price(txid, price_func, ccy) * txin_value/Decimal(COIN)
            self._coin_price_cache[cache_key] = result
            return result
        else:
            fiat_value = self.get_fiat_value(txid, ccy)
            if fiat_value is not None:
                return fiat_value
            else:
                p = self.price_at_timestamp(txid, price_func)
                return p * txin_value/Decimal(COIN)

    def is_billing_address(self, addr):
        # overridden for TrustedCoin wallets
        return False

    def is_watching_only(self) -> bool:
        raise NotImplementedError()

    def get_keystore(self) -> Optional[KeyStore]:
        return self.keystore

    def get_keystores(self) -> Sequence[KeyStore]:
        print('wallet:get_keystores: {}'.format(self.keystore.to_json()))
        return [self.keystore] if self.keystore else []

    def save_keystore(self):
        raise NotImplementedError()

    def has_seed(self) -> bool:
        raise NotImplementedError()

    def is_beyond_limit(self, address: str) -> bool:
        raise NotImplementedError()


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def _update_password_for_keystore(self, old_pw, new_pw):
        if self.keystore and self.keystore.may_have_password():
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())


class Imported_Wallet(Simple_Wallet):
    # wallet made of imported addresses

    wallet_type = 'imported'
    txin_type = 'address'

    def __init__(self, storage, *, config):
        Abstract_Wallet.__init__(self, storage, config=config)

    def is_watching_only(self):
        return self.keystore is None

    def can_import_privkey(self):
        return bool(self.keystore)

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore') if self.storage.get('keystore') else None

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def can_import_address(self):
        return self.is_watching_only()

    def can_delete_address(self):
        return True

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_change(self, address):
        return False

    def is_beyond_limit(self, address):
        return False

    def get_fingerprint(self):
        return ''

    def get_addresses(self):
        # note: overridden so that the history can be cleared
        return self.db.get_imported_addresses()

    def get_receiving_addresses(self, **kwargs):
        return self.get_addresses()

    def get_change_addresses(self, **kwargs):
        return []

    def import_addresses(self, addresses: List[str], *,
                         write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        good_addr = []  # type: List[str]
        bad_addr = []  # type: List[Tuple[str, str]]
        for address in addresses:
            if not bitcoin.is_address(address):
                bad_addr.append((address, _('invalid address')))
                continue
            if self.db.has_imported_address(address):
                bad_addr.append((address, _('address already in wallet')))
                continue
            good_addr.append(address)
            self.db.add_imported_address(address, {})
            self.add_address(address)
        if write_to_disk:
            self.storage.write()
        return good_addr, bad_addr

    def import_address(self, address: str) -> str:
        good_addr, bad_addr = self.import_addresses([address])
        if good_addr and good_addr[0] == address:
            return address
        else:
            raise BitcoinException(str(bad_addr[0][1]))

    def delete_address(self, address):
        if not self.db.has_imported_address(address):
            return
        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr in self.db.get_history():
                details = self.db.get_addr_history(addr)
                if addr == address:
                    for tx_hash, height in details:
                        transactions_to_remove.add(tx_hash)
                else:
                    for tx_hash, height in details:
                        transactions_new.add(tx_hash)
            transactions_to_remove -= transactions_new
            self.db.remove_addr_history(address)
            for tx_hash in transactions_to_remove:
                self.remove_transaction(tx_hash)
        self.set_label(address, None)
        self.remove_payment_request(address)
        self.set_frozen_state_of_addresses([address], False)
        pubkey = self.get_public_key(address)
        self.db.remove_imported_address(address)
        if pubkey:
            # delete key iff no other address uses it (e.g. p2pkh and p2wpkh for same key)
            for txin_type in bitcoin.WIF_SCRIPT_TYPES.keys():
                try:
                    addr2 = bitcoin.pubkey_to_address(txin_type, pubkey)
                except NotImplementedError:
                    pass
                else:
                    if self.db.has_imported_address(addr2):
                        break
            else:
                self.keystore.delete_imported_key(pubkey)
                self.save_keystore()
        self.storage.write()

    def is_mine(self, address) -> bool:
        return self.db.has_imported_address(address)

    def get_address_index(self, address) -> Optional[str]:
        # returns None if address is not mine
        return self.get_public_key(address)

    def get_public_key(self, address) -> Optional[str]:
        x = self.db.get_imported_address(address)
        return x.get('pubkey') if x else None

    def import_private_keys(self, keys: List[str], password: Optional[str], *,
                            write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        good_addr = []  # type: List[str]
        bad_keys = []  # type: List[Tuple[str, str]]
        for key in keys:
            try:
                txin_type, pubkey = self.keystore.import_privkey(key, password)
            except Exception as e:
                bad_keys.append((key, _('invalid private key') + f': {e}'))
                continue
            if txin_type not in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
                bad_keys.append((key, _('not implemented type') + f': {txin_type}'))
                continue
            addr = bitcoin.pubkey_to_address(txin_type, pubkey)
            good_addr.append(addr)
            self.db.add_imported_address(addr, {'type':txin_type, 'pubkey':pubkey})
            self.add_address(addr)
        self.save_keystore()
        if write_to_disk:
            self.storage.write()
        return good_addr, bad_keys

    def import_private_key(self, key: str, password: Optional[str]) -> str:
        good_addr, bad_keys = self.import_private_keys([key], password=password)
        if good_addr:
            return good_addr[0]
        else:
            raise BitcoinException(str(bad_keys[0][1]))

    def get_txin_type(self, address):
        return self.db.get_imported_address(address).get('type', 'address')

    def _add_input_sig_info(self, txin, address, *, only_der_suffix=True):
        if not self.is_mine(address):
            return
        if txin.script_type in ('unknown', 'address'):
            return
        elif txin.script_type in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
            pubkey = self.get_public_key(address)
            if not pubkey:
                return
            txin.pubkeys = [bfh(pubkey)]
        else:
            raise Exception(f'Unexpected script type: {txin.script_type}. '
                            f'Imported wallets are not implemented to handle this.')

    def pubkeys_to_address(self, pubkey):
        for addr in self.db.get_imported_addresses():
            if self.db.get_imported_address(addr)['pubkey'] == pubkey:
                return addr

class HsmGenerated_Wallet(Imported_Wallet):
    # wallet made of hsm generated addresses

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    wallet_type = 'hsmgenerated'
    headers = {'content-type': 'application/json'}

    #def dump(self):
    #    d = {
    #        'type': self.keystore_type,
    #        'pw_hash_version': 1,
    #        'keypairs': self.keypairs
    #    }
    #    return d

    #create wallet
    def create_wallet(self, params):
        self.approverID = params.get('approverID', '')
        self.approver_pub_key = params.get('approver_pub_key', '')
        self.keystore_type = params.get('keystore_type', '')
        self.sign_server_url = params.get('sign_server_url', '')
        self.crt_key_path = params.get('crt_key_path', '')
        params={'wallet_type': self.wallet_type, 'approver_public_key': self.approver_pub_key}
        resp = requests.post(self.sign_server_url, data=json.dumps(params), cert=self.crt_key_path, verify=False, headers=self.headers)
        try:
            print('create_wallet: resp=' + json.dumps(resp.json(), indent=4))
            wallet_id = resp.json()['wallet_id']
        except:
            print('create_wallet: resp=' + resp.text)
            wallet_id = ''
            
        self.wallet_id = wallet_id
        return wallet_id

    #create wallet key id
    def create_wallet_key(self, wallet_id):
        resp = requests.post(self.sign_server_url + '/' + wallet_id + "/keys", cert=self.crt_key_path, verify=False, headers=self.headers)
        try:
            print('create_wallet_key: resp=' + json.dumps(resp.json(), indent=4))
            wallet_item = resp.json()
            key_id = wallet_item['key_id']
            wallet_pub_key = wallet_item['wallet_public_key']
        except:
            print('create_wallet_key: resp=' + resp.text)
            key_id = ''
            wallet_pub_key = ''

        self.wallet_id = wallet_id
        self.key_id = key_id
        self.wallet_pub_key = wallet_pub_key
        self.set_keypair()
        return self.key_id, self.wallet_pub_key

    #dump and store wallet info into db
    def set_keypair(self):
        self.keypairs = {
            self.wallet_pub_key: {
                'approver_id': self.approverID, 
                'key_id': self.key_id,
                'wallet_id': self.wallet_id
            }
        }

    #return wallet info which stored in 'default_wallet'
    def get_wallet_info(self, storage):
        
        keystore = storage.get('keystore', '')
        keypair = keystore.get('keypairs', '')
        
        values = list(keypair.values())[0]

        print(values)
        for key in values:
            if key == 'approver_id':
                approver_id = values[key]
            elif key == 'key_id':
                key_id = values[key]
            else:
                wallet_id = values[key]

        return key_id, wallet_id, approver_id
    
    def make_unsigned_transaction(self, *, coins: Sequence[PartialTxInput],
                                  outputs: List[PartialTxOutput], fee=None,
                                  change_addr: str = None, is_sweep=False) -> PartialHsmTransaction:
        tx = super().make_unsigned_transaction(coins=coins, outputs=outputs, fee=fee, change_addr=change_addr, is_sweep=is_sweep)
        # `Downcasts` a PartialTransaction object to a PartialHsmTransaction object
        # print('HsmGenerated_Wallet.make_unsigned_transaction: downcasting tx')
        tx = PartialHsmTransaction.from_tx(tx)
        return tx

    def get_unused_addresses(self):
        domain = self.get_receiving_addresses()
        # FIXME: need to generate more keys on HSM while we are reusing keys for now
        in_use = [k for k in self.receive_requests.keys() if self.get_request_status(k)[0] != PR_EXPIRED]
        return [addr for addr in domain if addr not in in_use]

    def import_keyrecords(self, keyrecords: List[dict], password: Optional[str], *,
                          write_to_disk=True) -> Tuple[List[str], List[Tuple[str, str]]]:
        good_addr = []  # type: List[str]
        bad_keys = []  # type: List[Tuple[str, str]]
        for keyrecord in keyrecords:
            self.keystore.import_keyrecord(keyrecord)
            # FIXME: support more txin types
            txin_type = 'p2pkh'
            pubkey = keyrecord['pubKey']
            addr = bitcoin.pubkey_to_address(txin_type, pubkey)
            good_addr.append(addr)
            self.db.add_imported_address(addr, {'type':txin_type, 'pubkey':pubkey})
            self.add_address(addr)
        self.save_keystore()
        if write_to_disk:
            self.storage.write()
        return good_addr, bad_keys

class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage, *, config):
        self._ephemeral_addr_to_addr_index = {}  # type: Dict[str, Sequence[int]]
        Abstract_Wallet.__init__(self, storage, config=config)
        self.gap_limit = storage.get('gap_limit', 20)
        # generate addresses now. note that without libsecp this might block
        # for a few seconds!
        self.synchronize()

    def has_seed(self):
        return self.keystore.has_seed()

    def get_addresses(self):
        # note: overridden so that the history can be cleared.
        # addresses are ordered based on derivation
        out = self.get_receiving_addresses()
        out += self.get_change_addresses()
        return out

    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None):
        return self.db.get_receiving_addresses(slice_start=slice_start, slice_stop=slice_stop)

    def get_change_addresses(self, *, slice_start=None, slice_stop=None):
        return self.db.get_change_addresses(slice_start=slice_start, slice_stop=slice_stop)

    @profiler
    def try_detecting_internal_addresses_corruption(self):
        if not is_using_fast_ecc():
            self.logger.info("internal address corruption test skipped due to missing libsecp256k1")
            return
        addresses_all = self.get_addresses()
        # sample 1: first few
        addresses_sample1 = addresses_all[:10]
        # sample2: a few more randomly selected
        addresses_rand = addresses_all[10:]
        addresses_sample2 = random.sample(addresses_rand, min(len(addresses_rand), 10))
        for addr_found in addresses_sample1 + addresses_sample2:
            self.check_address(addr_found)

    def check_address(self, addr):
        print('wallet:check_address addr={}'.format(addr))
        if addr and self.is_mine(addr):
            addr2 = self.derive_address(*self.get_address_index(addr))
            if addr != addr2: # self.derive_address(*self.get_address_index(addr)):
                print('wallet:check_address addr={} {}'.format(addr, addr2))
                raise InternalAddressCorruption()

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def add_seed(self, seed, pw):
        self.keystore.add_seed(seed, pw)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.min_acceptable_gap():
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            self.storage.write()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for addr in addresses[::-1]:
            if self.db.get_addr_history(addr):
                break
            k += 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for addr in addresses[0:-k]:
            if self.db.get_addr_history(addr):
                n = 0
            else:
                n += 1
                nmax = max(nmax, n)
        return nmax + 1

    def derive_address(self, for_change, n):
        print('wallet:deterministic:derive_addresses for_chnage={} n={}'.format(for_change, n))
        x = self.derive_pubkeys(for_change, n)
        print('wallet:deterministic:derive_addresses pubkeys={}'.format(x))
        #return self.pubkeys_to_address(x)
        adr = self.pubkeys_to_address(x)
        print('wallet:deterministic:derive_addresses pubkey={} address={}'.format(x, adr))
        return adr

    def get_public_keys_with_deriv_info(self, address: str):
        der_suffix = self.get_address_index(address)
        print('get_public_keys_with_deriv_info: address={} der_suffix={}'.format(address, der_suffix))
        der_suffix = [int(x) for x in der_suffix]
        #return {k.derive_pubkey(*der_suffix): (k, der_suffix)
        #        for k in self.get_keystores()}
        resp = {k.derive_pubkey(*der_suffix): (k, der_suffix)
                for k in self.get_keystores()}
        # address: the coin address to spend
        # resp: list of public keys that correspond to the address
        print('***get_public_keys_with_deriv_info: address={} der_suffix={} resp={}'.format(address, '/'.join([str(x) for x in der_suffix]), resp))
        return resp

    def _add_input_sig_info(self, txin, address, *, only_der_suffix=True):
        self._add_txinout_derivation_info(txin, address, only_der_suffix=only_der_suffix)

    def _add_txinout_derivation_info(self, txinout, address, *, only_der_suffix=True):
        if not self.is_mine(address):
            return
        pubkey_deriv_info = self.get_public_keys_with_deriv_info(address)
        txinout.pubkeys = sorted([bfh(pk) for pk in list(pubkey_deriv_info)])
        print('***Deterministic_wallet:_add_txinout_derivation_info address={} pubkey_deriv_info={} txinout={}'.format(address, pubkey_deriv_info, txinout.to_json()))
        ## Here we find the pubkey of a coin address to be spent
        for pubkey_hex in pubkey_deriv_info:
            ks, der_suffix = pubkey_deriv_info[pubkey_hex]
            if hasattr(ks, 'xpub'):
                print('***Deterministic_wallet:_add_txinout_derivation_info der_suffix={} ks.xpub={} pubkey_hex={} pubkey={}'.format(der_suffix, ks.xpub, pubkey_hex, BIP32Node.from_xkey(ks.xpub).eckey.get_public_key_bytes().hex()))
            else:
                print('***Deterministic_wallet:_add_txinout_derivation_info der_suffix={} pubkey_hex={}'.format(der_suffix, pubkey_hex))
            fp_bytes, der_full = ks.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix,
                                                                                   only_der_suffix=only_der_suffix)
            # pubkey_hex: the coin address to spend
            #
            txinout.bip32_paths[bfh(pubkey_hex)] = (fp_bytes, der_full)
        print('***_add_input_sig_info: txinout={}'.format(txinout.to_json()))

    def create_new_address(self, for_change=False):
        print('wallet:create_new_address for_change={}'.format(for_change))
        assert type(for_change) is bool
        with self.lock:
            n = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
            address = self.derive_address(for_change, n)
            self.db.add_change_address(address) if for_change else self.db.add_receiving_address(address)
            self.add_address(address)
            if for_change:
                # note: if it's actually used, it will get filtered later
                self._unused_change_addresses.append(address)
            print('wallet:create_new_address: address={} for_change={}'.format(address, for_change))
            return address

    def synchronize_sequence(self, for_change):
        # print('wallet:syncrhonize_sequence {}'.format(for_change))
        limit = self.gap_limit_for_change if for_change else self.gap_limit
        while True:
            num_addr = self.db.num_change_addresses() if for_change else self.db.num_receiving_addresses()
            #print('synchronize_sequence: limit={} num_addr={}'.format(limit, num_addr))
            if num_addr < limit:
                # print('synchronize_sequence: limit={} num_addr={} calling create_new_address'.format(limit, num_addr))
                self.create_new_address(for_change)
                continue
            if for_change:
                last_few_addresses = self.get_change_addresses(slice_start=-limit)
            else:
                last_few_addresses = self.get_receiving_addresses(slice_start=-limit)
            if any(map(self.address_is_old, last_few_addresses)):
                # print('synchronize_sequence: calling create_new_address due to old address')
                self.create_new_address(for_change)
            else:
                break
        # print('wallet:syncrhonize_sequence returning')

    @AddressSynchronizer.with_local_height_cached
    def synchronize(self):
        with self.lock:
            self.synchronize_sequence(False)
            self.synchronize_sequence(True)
        # print('synchronize: returning')

    def is_beyond_limit(self, address):
        is_change, i = self.get_address_index(address)
        limit = self.gap_limit_for_change if is_change else self.gap_limit
        if i < limit:
            return False
        slice_start = max(0, i - limit)
        slice_stop = max(0, i)
        if is_change:
            prev_addresses = self.get_change_addresses(slice_start=slice_start, slice_stop=slice_stop)
        else:
            prev_addresses = self.get_receiving_addresses(slice_start=slice_start, slice_stop=slice_stop)
        for addr in prev_addresses:
            if self.db.get_addr_history(addr):
                return False
        return True

    def get_address_index(self, address) -> Optional[Sequence[int]]:
        return self.db.get_address_index(address) or self._ephemeral_addr_to_addr_index.get(address)

    def _learn_derivation_path_for_address_from_txinout(self, txinout, address):
        for ks in self.get_keystores():
            pubkey, der_suffix = ks.find_my_pubkey_in_txinout(txinout, only_der_suffix=True)
            if der_suffix is not None:
                self._ephemeral_addr_to_addr_index[address] = list(der_suffix)
                return True
        return False

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, storage, *, config):
        print('wallet:Simple_Deterministic_Wallet:__init__')
        Deterministic_Wallet.__init__(self, storage, config=config)

    def get_public_key(self, address):
        print('wallet:Simple_Deterministic_Wallet:get_public_key address={}'.format(address))
        sequence = self.get_address_index(address)
        pubkey = self.derive_pubkeys(*sequence)
        return pubkey

    def load_keystore(self):
        print('wallet:Simple_Deterministic_Wallet:load_keystore')
        self.keystore = load_keystore(self.storage, 'keystore')
        try:
            xtype = bip32.xpub_type(self.keystore.xpub)
        except:
            xtype = 'standard'
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype

    def get_master_public_key(self):
        print('wallet:Simple_Deterministic_Wallet:get_master_public_key')
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        print('wallet:Simple_Deterministic_Wallet:derive_pubkeys c={} i={}'.format(c, i))
        return self.keystore.derive_pubkey(c, i)

class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        address = bitcoin.pubkey_to_address(self.txin_type, pubkey)
        print('wallet:Standard_wallet:pubkeys_to_address pubkey={} txin_type={} address={}'.format(pubkey, self.txin_type, address))
        return address

class Bip32Hsm_Wallet(Standard_Wallet):
    # wallet made with bip32 hsm
    
    wallet_type = 'bip32hsm'

    def __init__(self, storage, *, config):
        print('wallet:Bip32Hsm_Wallet:__init__')
        Simple_Deterministic_Wallet.__init__(self, storage, config=config)

    def export_private_key(self, address, password) -> str:
        raise NotImplementedError()  # not supported

    def can_export(self):
        return False

    def load_keystore(self):
        print('wallet:Bip32Hsm_Wallet:load_keystore')
        self.keystore = load_keystore(self.storage, 'keystore')
        #xtype = 'standard'
        xtype = self.keystore.xtype
        self.txin_type = 'p2pkh' if xtype == 'standard' else xtype
        print('wallet:Bip32Hsm_Wallet:load_keystore: dump={}'.format(json.dumps(self.keystore.short_dump(), indent=4)))
        print('wallet:Bip32Hsm_Wallet:load_keystore: xtype={} txin_type={}'.format(xtype, self.txin_type))

    def get_public_key(self, address) -> Optional[str]:
        pubkeyBytes = self.keystore.get_public_key(address)
        if pubkeyBytes is None:
            # Call Simple_Deterministic_Wallet.get_public_key
            pubkeyBytes = super().get_public_key(address)
        return pubkeyBytes

    # Copied from Imported_Wallet class
    def _add_input_sig_info(self, txin, address, *, only_der_suffix=True):
        print('wallet:Bip32Hsm_Wallet:_add_input_sig_info txin={} script_type={}'.format(txin.to_json(), txin.script_type))
        if not self.is_mine(address):
            return
        if txin.script_type in ('unknown', 'address'):
            return
        elif txin.script_type in ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh'):
            pubkey = self.get_public_key(address)
            if not pubkey:
                return
            txin.pubkeys = [bfh(pubkey)]
        else:
            raise Exception(f'Unexpected script type: {txin.script_type}. '
                            f'Imported wallets are not implemented to handle this.')
        print('wallet:Bip32Hsm_Wallet:_add_input_sig_info txin={} pubkeys={}'.format(txin.to_json(), txin.pubkeys))

    def pubkeys_to_address(self, pubkey):
        adr = bitcoin.pubkey_to_address(self.txin_type, pubkey)
        print('wallet:Bip32Hsm_wallet:pubkeys_to_address pubkey={} txin_type={} address={}'.format(pubkey, self.txin_type, adr))
        return adr

    def make_unsigned_transaction(self, *, coins: Sequence[PartialTxInput],
                                  outputs: List[PartialTxOutput], fee=None,
                                  change_addr: str = None, is_sweep=False) -> PartialHsmTransaction:
        print('Bip32Hsm_Wallet:make_unsigned_transaction')
        tx = super().make_unsigned_transaction(coins=coins, outputs=outputs, fee=fee, change_addr=change_addr, is_sweep=is_sweep)
        # `Downcasts` a PartialTransaction object to a PartialBip32HsmTransaction object
        # tx = PartialBip32HsmTransaction.from_tx(tx)
        bip32HsmTx = PartialBip32HsmTransaction.cast(tx)
        print('wallet:Bip32Hsm_Wallet:make_unsigned_transaction tx={} {}'.format(tx, tx.to_json()))
        print('wallet:Bip32Hsm_Wallet:make_unsigned_transaction bip32HsmTx={} {}'.format(bip32HsmTx, bip32HsmTx.to_json()))
        return bip32HsmTx

class DAP_Wallet(Bip32Hsm_Wallet):
    wallet_type = 'dap'

    def make_unsigned_transaction(self, *, coins: Sequence[PartialTxInput],
                                  outputs: List[PartialTxOutput], fee=None,
                                  change_addr: str = None, is_sweep=False) -> PartialHsmTransaction:
        print('DAP_Wallet:make_unsigned_transaction')
        tx = super().make_unsigned_transaction(coins=coins, outputs=outputs, fee=fee, change_addr=change_addr, is_sweep=is_sweep)
        # `Downcasts` a PartialTransaction object to a PartialDAPTransaction object
        # tx = PartialDAPTransaction.from_tx(tx)
        dapTx = PartialDAPTransaction.cast(tx)
        print('wallet:DAP_Wallet:make_unsigned_transaction tx={} {}'.format(tx, tx.to_json()))
        print('wallet:DAP_Wallet:make_unsigned_transaction dapTx={} {}'.format(dapTx, dapTx.to_json()))
        total_amount = 0.0
        for output in outputs:
            if output.value is None:
                pass
            elif type(output.value) is str and output.value == '!':
                total_amount = 'max'
                break
            else:
                total_amount += float(output.value / COIN)
        dapTx.set_total_amount(total_amount)
        print('wallet:DAP_Wallet:make_unsigned_transaction total_amount={}'.format(total_amount))
        return dapTx

    def get_signed_transaction(self, tx: Transaction, password) -> Optional[PartialTransaction]:
        print('DAP_Wallet:get_signed_transaction tx={}'.format(tx.to_json()))
        tx = PartialDAPTransaction.cast(tx)
        print('DAP_Wallet:get_signed_transaction dapTx={}'.format(tx.to_json()))
        if self.is_watching_only():
            return
        if not isinstance(tx, PartialTransaction):
            return
        # add info to a temporary tx copy; including xpubs
        # and full derivation paths as hw keystores might want them
        tmp_tx = copy.deepcopy(tx)
        tmp_tx.add_info_from_wallet(self, include_xpubs_and_full_paths=True)
        # sign. start with ready keystores.
        found = True
        for k in sorted(self.get_keystores(), key=lambda ks: ks.ready_to_sign(), reverse=True):
            try:
                if k.can_sign(tmp_tx):
                    found = k.get_signed_transaction(tmp_tx, password)
                    if found == False:
                        break
            except UserCancelled:
                continue
        # remove sensitive info; then copy back details from temporary tx
        tmp_tx.remove_xpubs_and_bip32_paths()
        tx.combine_with_other_psbt(tmp_tx)
        tx.add_info_from_wallet(self, include_xpubs_and_full_paths=False)
        print('DAP_Wallet:get_signed_transaction added tx={}'.format(tx.to_json()))
        print('DAP_Wallet:get_signed_transaction added tx={}'.format(tx))
        print('DAP_Wallet:get_signed_transaction added found={}'.format(found))
        return found

class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n

    def __init__(self, storage, *, config):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage, config=config)

    def get_public_keys(self, address):
        return list(self.get_public_keys_with_deriv_info(address))

    def pubkeys_to_address(self, pubkeys):
        redeem_script = self.pubkeys_to_scriptcode(pubkeys)
        return bitcoin.redeem_script_to_address(self.txin_type, redeem_script)

    def pubkeys_to_scriptcode(self, pubkeys: Sequence[str]) -> str:
        return transaction.multisig_script(sorted(pubkeys), self.m)

    def get_redeem_script(self, address):
        txin_type = self.get_txin_type(address)
        pubkeys = self.get_public_keys(address)
        scriptcode = self.pubkeys_to_scriptcode(pubkeys)
        if txin_type == 'p2sh':
            return scriptcode
        elif txin_type == 'p2wsh-p2sh':
            return bitcoin.p2wsh_nested_script(scriptcode)
        elif txin_type == 'p2wsh':
            return None
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def get_witness_script(self, address):
        txin_type = self.get_txin_type(address)
        pubkeys = self.get_public_keys(address)
        scriptcode = self.pubkeys_to_scriptcode(pubkeys)
        if txin_type == 'p2sh':
            return None
        elif txin_type in ('p2wsh-p2sh', 'p2wsh'):
            return scriptcode
        raise UnknownTxinType(f'unexpected txin_type {txin_type}')

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']
        xtype = bip32.xpub_type(self.keystore.xpub)
        self.txin_type = 'p2sh' if xtype == 'standard' else xtype
        print('load_keystore: {}'.format(self.get_keystores()))

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def can_have_keystore_encryption(self):
        return any([k.may_have_password() for k in self.get_keystores()])

    def _update_password_for_keystore(self, old_pw, new_pw):
        for name, keystore in self.keystores.items():
            if keystore.may_have_password():
                keystore.update_password(old_pw, new_pw)
                self.storage.put(name, keystore.dump())

    def check_password(self, password):
        for name, keystore in self.keystores.items():
            if keystore.may_have_password():
                keystore.check_password(password)
        self.storage.check_password(password)

    def get_available_storage_encryption_version(self):
        # multisig wallets are not offered hw device encryption
        return StorageEncryptionVersion.USER_PASSWORD

    def has_seed(self):
        return self.keystore.has_seed()

    def is_watching_only(self):
        return all([k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))


wallet_types = ['standard', 'multisig', 'imported', 'hsmgenerated', 'bip32hsm', 'dap']

def register_wallet_type(category):
    wallet_types.append(category)

wallet_constructors = {
    'standard': Standard_Wallet,
    'old': Standard_Wallet,
    'xpub': Standard_Wallet,
    'imported': Imported_Wallet,
    'hsmgenerated': HsmGenerated_Wallet,
    'bip32hsm': Bip32Hsm_Wallet,
    'dap': DAP_Wallet
}

def register_constructor(wallet_type, constructor):
    wallet_constructors[wallet_type] = constructor

# former WalletFactory
class Wallet(object):
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    def __new__(self, storage: WalletStorage, *, config: SimpleConfig):
        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        wallet = WalletClass(storage, config=config)
        return wallet

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise WalletFileException("Unknown wallet type: " + str(wallet_type))


def create_new_wallet(*, path, config: SimpleConfig, passphrase=None, password=None,
                      encrypt_file=True, seed_type=None, gap_limit=None) -> dict:
    """Create a new wallet"""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    seed = Mnemonic('en').make_seed(seed_type)
    print('create_new_wallet: seed_type={} seed={}'.format(seed_type, seed))
    k = keystore.from_seed(seed, passphrase)
    storage.put('keystore', k.dump())
    storage.put('wallet_type', 'standard')
    if gap_limit is not None:
        storage.put('gap_limit', gap_limit)
    wallet = Wallet(storage, config=config)
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = "Please keep your seed in a safe place; if you lose it, you will not be able to restore your wallet."

    _keystore = k.dump()
    _xpub_node = BIP32Node.from_xkey(_keystore['xpub'])
    print('create_new_wallet: keystore={} pubkey={} fingerprint={}'.format(_keystore, _xpub_node.eckey.get_public_key_bytes().hex(), _xpub_node.calc_fingerprint_of_this_node().hex()))
    return {'seed': seed, 'wallet': wallet, 'msg': msg}

def create_bip32hsm_wallet(*, path, config: SimpleConfig, passphrase=None, password=None,
                      encrypt_file=True, seed_type=None, gap_limit=None) -> dict:
    """Create a new wallet"""
    print('create_bip32hsm_wallet: seed_type={} path={} gap_limit={}'.format(seed_type, path, gap_limit))
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    k = keystore.Bip32Hsm_KeyStore({}, wallet_type=seed_type)
    storage.put('keystore', k.dump())
    storage.put('wallet_type', 'bip32hsm')
    if gap_limit is not None:
        storage.put('gap_limit', gap_limit)
    wallet = Bip32Hsm_Wallet(storage, config=config)
    #wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = "Please keep your seed in a safe place; if you lose it, you will not be able to restore your wallet."

    wallet.storage.put('keystore', wallet.keystore.dump())

    wallet.storage.write()
    print('create_bip32hsm_wallet: write completed')
    return {'wallet': wallet, 'msg': msg}

def create_dap_wallet(*, userid, password, path, host, port, seedid, watch_only, config: SimpleConfig, passphrase=None,
                      encrypt_file=True, seed_type=None, gap_limit=None) -> dict:
    """Create a new wallet"""
    print('create_dap_wallet: path={} gap_limit={}'.format(path, gap_limit))
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    #seed = Mnemonic('en').make_seed(seed_type)
    #print('create_new_wallet: seed_type={} seed={}'.format(seed_type, seed))
    d = {'userid': userid, 'password': password, 'host': host, 'port': port, 'watch_only': watch_only}
    if seedid is not None:
        d['seedid'] = seedid
    k = keystore.DAP_KeyStore(d, wallet_type=seed_type)
    storage.put('keystore', k.dump())
    storage.put('wallet_type', 'dap')
    if gap_limit is not None:
        storage.put('gap_limit', gap_limit)
    wallet = DAP_Wallet(storage, config=config)
    #wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = "This is your wallet."

    wallet.storage.put('keystore', wallet.keystore.dump())

    wallet.storage.write()
    print('create_dap_wallet: write completed')
    return {'wallet': wallet, 'msg': msg}

def restore_wallet_from_text(text, *, path, config: SimpleConfig,
                             passphrase=None, password=None, encrypt_file=True,
                             gap_limit=None) -> dict:
    """Restore a wallet from text. Text can be a seed phrase, a master
    public key, a master private key, a list of bitcoin addresses
    or bitcoin private keys."""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    text = text.strip()
    if keystore.is_address_list(text):
        wallet = Imported_Wallet(storage, config=config)
        addresses = text.split()
        good_inputs, bad_inputs = wallet.import_addresses(addresses, write_to_disk=False)
        # FIXME tell user about bad_inputs
        if not good_inputs:
            raise Exception("None of the given addresses can be imported")
    elif keystore.is_private_key_list(text, allow_spaces_inside_key=False):
        k = keystore.Imported_KeyStore({})
        storage.put('keystore', k.dump())
        wallet = Imported_Wallet(storage, config=config)
        keys = keystore.get_private_keys(text, allow_spaces_inside_key=False)
        good_inputs, bad_inputs = wallet.import_private_keys(keys, None, write_to_disk=False)
        # FIXME tell user about bad_inputs
        if not good_inputs:
            raise Exception("None of the given privkeys can be imported")
    else:
        if keystore.is_master_key(text):
            k = keystore.from_master_key(text)
        elif keystore.is_seed(text):
            k = keystore.from_seed(text, passphrase)
        else:
            raise Exception("Seed or key not recognized")
        storage.put('keystore', k.dump())
        storage.put('wallet_type', 'standard')
        if gap_limit is not None:
            storage.put('gap_limit', gap_limit)
        wallet = Wallet(storage, config=config)

    assert not storage.file_exists(), "file was created too soon! plaintext keys might have been written to disk"
    wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    wallet.synchronize()
    msg = ("This wallet was restored offline. It may contain more addresses than displayed. "
           "Start a daemon and use load_wallet to sync its history.")

    wallet.storage.write()
    return {'wallet': wallet, 'msg': msg}

import requests

def create_hsm_wallet(*, path, config: SimpleConfig,
                      passphrase=None, password=None, encrypt_file=True,
                      gap_limit=None) -> dict:
    """Create a wallet from a private key generated at hsm."""
    storage = WalletStorage(path)
    if storage.file_exists():
        raise Exception("Remove the existing wallet first!")

    # call policy service and wallet service
    
    if not os.environ.get('APPROVER_EMAIL'):
        raise Exception("undegined APPROVER_EMAIL (<email address>)")
    approver_email = os.environ['APPROVER_EMAIL']
    
    if not os.environ.get('POLICY_SERVICE_HOST'):
        raise Exception("undefined POLICY_SERVICE_HOST (<address>:<port>)")
    policy_server_url = 'https://' + os.environ['POLICY_SERVICE_HOST']

    if not os.environ.get('POLICY_CLIENT_CRT_KEY'):
        raise Exception("undefined POLICY_CLIENT_CRT_KEY")
    policy_crt_key_path = '/data/' + os.environ['POLICY_CLIENT_CRT_KEY']

    # approver_email = "tester1@ibm.com"
    # policy_server_url = "https://localhost:443"
    # policy_crt_key_path = '/blockchain/dev/DigitalAssets-policyService/.localhost-policy-service'

    k = keystore.HsmGenerated_KeyStore({'policy_server_url': policy_server_url, 'policy_crt_key_path': policy_crt_key_path, 'approver_email': approver_email})
    approverID, approver_pub_key = k.create_approver_id()
    keystore_type = k.type
    storage.put('keystore', k.dump())
    
    # send public key and wallet_type to signing service
    if not os.environ.get('SIGNING_SERVICE_HOST'):
        raise Exception("undefined SIGNING_SERVICE_HOST (<address>:<port>)")
    sign_server_url = 'https://' + os.environ['SIGNING_SERVICE_HOST'] + '/v1/wallets'

    if not os.environ.get('CLIENT_CRT_KEY'):
        raise Exception("undefined CLIENT_CRT_KEY")
    crt_key_path = '/data/' + os.environ['CLIENT_CRT_KEY']
    
    # TODO: obtain a client certificate key content (rather than path name) to store it in a file, and pass the path name to wallet.create_wallet()
    #crt_key_path = '/data/signing-service-client-crt-key'
    #with open(crt_key_path, 'w') as f:
    #    f.write(os.environ['CLIENT_CRT_KEY'])

    wallet = HsmGenerated_Wallet(storage, config=config)
    params = {'sign_server_url': sign_server_url, 'crt_key_path': crt_key_path, 'approverID': approverID, 'approver_pub_key': approver_pub_key, 'keystore_type': keystore_type}
    wallet_id = wallet.create_wallet(params)
    key_id, wallet_pub_key = wallet.create_wallet_key(wallet_id)

    keyrecord = {}
    keyrecord['pubKey'] = wallet_pub_key
    keyrecord['info'] = {
        'approver_id': approverID,
        'approver_pub_key': approver_pub_key,
        'key_id': key_id,
        'wallet_id': wallet_id
    }
    wallet.import_keyrecords([keyrecord], None, write_to_disk=False)

    assert not storage.file_exists(), "file was created too soon! plaintext keys might have been written to disk"
    #wallet.update_password(old_pw=None, new_pw=password, encrypt_storage=encrypt_file)
    #wallet.synchronize()
    msg = ("This wallet was restored offline. It may contain more addresses than displayed. "
           "Start a daemon and use load_wallet to sync its history.")

    wallet.storage.write()
    return {'wallet': wallet, 'msg': msg}
