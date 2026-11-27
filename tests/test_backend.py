# SPDX-License-Identifier: MIT
"""evmbackend.py (minimal build) without lightningd: the send path against
anvil (already in chain, missing inputs, revert names, the gas cap, receipts
making a child's prevouts available, an unmined send outbid at its nonce),
the read methods, the RPCs, the hooks' decisions, the option check, the
alarms, and secrets kept out of logs. The plugin's methods are called
directly, with a fake log and a fake lightningd RPC."""
import json
import os
import re
import stat
import threading

import pytest

import btc
import evm
import evmbackend as eb
from conftest import CONTRACTS, SAT, Key, free_port, sign

A = Key(0xA11CE)
INTERVAL = 2
EXIT_TO = '0x000000000000000000000000000000000000dEaD'


# ------------------------------------------------------------ fixtures

class Log:
    def __init__(self):
        self.lines = []
        self.lock = threading.Lock()

    def __call__(self, level, msg):
        with self.lock:
            self.lines.append((level, msg))

    def at(self, level):
        return [m for lv, m in self.lines if lv == level]

    def text(self):
        return '\n'.join('{} {}'.format(lv, m) for lv, m in self.lines)


class FakeLn:
    """lightningd's RPC: canned answers per method."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        a = self.answers[method]
        return a(params) if callable(a) else a


def make_cfg(tmp_path, url='http://127.0.0.1:1', contract='0x' + '11' * 20, key=None, secrets=(), min_eth=0.01):
    key = key or os.urandom(32)
    return eb.Config(url, evm.checksum_address(contract), key, str(tmp_path / 'evm-key'), 'safe', 1.0,
                     int(min_eth * 10**18), str(tmp_path), secrets=list(secrets) + [url, key.hex()])


def offline_backend(tmp_path, ln=None, log=None, checked=True):
    """A Backend for the hook tests: no EVM node, options checked and fine,
    a funded key."""
    b = eb.Backend(make_cfg(tmp_path), log or Log(), lnrpc=(lambda: ln) if ln else None)
    b.interval = INTERVAL
    b._chain_id = 31337
    if checked:
        b.apply_option_check(GOOD_CONFIGS, GOOD_INFO)
    b.balance = 10**18
    return b


def start(chain, tmp_path):
    """A Backend on a fresh contract with a funded key (no poll or
    option-check thread: tests drive those)."""
    log = Log()
    b = eb.Backend(make_cfg(tmp_path, chain.rpc.url, chain.address), log)
    chain.rpc.call('anvil_setBalance', b.address, evm.qty(10**20))
    chain.mine_at(1)
    b.connect(retry_for=0)
    b.apply_option_check(GOOD_CONFIGS, GOOD_INFO)
    b.log_capture = log
    return b


@pytest.fixture
def backend(chain, tmp_path):
    b = start(chain, tmp_path)
    yield b
    b.stop()
    b.ix.close()


def deposit(chain, b, key=A, sats=100_000):
    rc = chain.deposit(key.p2wpkh, sats)
    b.ix.sync()
    log = [x for x in rc['logs'] if x['topics'][0] == '0x' + evm.keccak256(b'TxApplied(uint32,bytes32,bytes)').hex()][0]
    txid = evm.unhex(log['topics'][2])
    return txid, evm.abi_decode(['bytes'], evm.unhex(log['data']))[0]


def spend(b, prev_txid, vout, amount, key=A, out_script=None, fee=1000, locktime=0, sequence=0xffffffff):
    u = b.ix.utxo_internal(prev_txid, vout)
    assert u is not None
    tx = btc.Tx(2, [btc.TxIn(prev_txid, vout, b'', sequence)],
                [(amount - fee, out_script or key.p2wpkh)], locktime)
    return sign(tx, [key], [(u['amount'], u['script'], u['height'])])


def send(b, tx):
    return b.sendrawtransaction(tx.serialize().hex())


# ------------------------------------------------------------ the selector table

def _sol_errors():
    src = open(os.path.join(CONTRACTS, 'src', 'Errors.sol')).read()
    out = set()
    for m in re.finditer(r'^error\s+(\w+)\(([^)]*)\)\s*;', src, re.M):
        args = [a.strip().split()[0] for a in m.group(2).split(',') if a.strip()]
        out.add('{}({})'.format(m.group(1), ','.join(args)))
    return out


def test_selector_table_matches_errors_sol_and_abi():
    for sel, sig in eb.ERRORS.items():
        assert evm.selector(sig).hex() == sel, sig
    ours = set(eb.ERRORS.values()) - {'Error(string)', 'Panic(uint256)'}
    assert ours == _sol_errors()
    abi_errors = set()
    for name in ('UtxoChain', 'UtxoChainToken'):         # ETH and token mode (SPEC 4.6)
        artifact = os.path.join(CONTRACTS, 'out', name + '.sol', name + '.json')
        if not os.path.exists(artifact):
            pytest.skip('contracts/evm/out not built')
        abi = json.load(open(artifact))['abi']
        abi_errors |= {'{}({})'.format(e['name'], ','.join(i['type'] for i in e['inputs'])) for e in abi
                       if e['type'] == 'error'}
    assert abi_errors == ours


def eb_sel(sig):
    return evm.selector(sig).hex()


def test_revert_reason_decoding():
    def err(data, code=3):
        return evm.EvmError('eth_call: JSON-RPC error 3', code, data)
    assert eb.revert_reason(err('0x' + eb_sel('NonFinal()'))) == 'NonFinal'
    assert eb.revert_reason(err('0x' + eb_sel('BadSignature(uint256)') + (1).to_bytes(32, 'big').hex())) \
        == 'BadSignature(1)'
    assert eb.revert_reason(err({'data': '0x' + eb_sel('TooEarly()')})) == 'TooEarly'
    assert eb.revert_reason(err('0x' + eb_sel('Error(string)') + evm.abi_encode(['string'], ['boom']).hex())) \
        == 'Error'          # the node's text is never copied
    assert eb.revert_reason(err('0x' + eb_sel('Panic(uint256)') + (0x11).to_bytes(32, 'big').hex())) \
        == 'Panic(0x11)'
    assert eb.revert_reason(err('0xdeadbeef')) == 'reverted with an unknown error'
    assert eb.revert_reason(err(None)) == 'reverted'
    assert eb.revert_reason(err('0x')) == 'reverted'
    # A revert is told from a failing node by its data or code 3 only.
    assert eb.is_revert(err('0x')) and eb.is_revert(err(None)) and eb.is_revert(err('0x', code=-32000))
    assert not eb.is_revert(evm.EvmError('eth_call: URLError')) and not eb.is_revert(err(None, code=-32005))


# ------------------------------------------------------------ the send path, on anvil

def test_already_in_chain_sends_nothing(chain, backend):
    assert backend.token is None and backend.units_per_sat == eb.SAT_WEI    # a UtxoChain: ETH mode
    txid, raw = deposit(chain, backend)
    n = chain.rpc.nonce(backend.address)
    assert backend.sendrawtransaction(raw.hex()) == {'success': True, 'errmsg': ''}
    # and a submitted tx, re-sent
    tx = spend(backend, txid, 0, 100_000)
    assert send(backend, tx)['success']
    n2 = chain.rpc.nonce(backend.address)
    assert send(backend, tx)['success']
    assert chain.rpc.nonce(backend.address) == n2 == n + 1


def test_missing_or_spent_inputs(chain, backend):
    tx = btc.Tx(2, [btc.TxIn(os.urandom(32), 0)], [(1000, A.p2wpkh)], 0, [[b'\x01']])
    assert send(backend, tx) == {'success': False, 'errmsg': 'missing or spent inputs'}
    txid, _ = deposit(chain, backend)
    t1 = spend(backend, txid, 0, 100_000, fee=1000)
    t2 = spend(backend, txid, 0, 100_000, fee=2000)     # a double spend of the same deposit
    assert send(backend, t1)['success']
    assert send(backend, t2)['errmsg'] == 'missing or spent inputs'


def test_bad_tx_does_not_parse(backend):
    assert backend.sendrawtransaction('00ff')['errmsg'] == 'the transaction does not parse'
    assert backend.sendrawtransaction('zz')['errmsg'] == 'the transaction does not parse'


def test_revert_names(chain, backend):
    txid, _ = deposit(chain, backend)
    tx = spend(backend, txid, 0, 100_000)
    sig = bytearray(tx.witnesses[0][0])
    sig[10] ^= 1
    tx.witnesses[0][0] = bytes(sig)
    n = chain.rpc.nonce(backend.address)
    r = send(backend, tx)
    assert not r['success'] and re.fullmatch(r'Bad\w+\(0\)', r['errmsg']), r
    # A height lock far ahead: NonFinal, and CLN will retry it.
    h = chain.height_now()
    late = spend(backend, txid, 0, 100_000, locktime=h + 50, sequence=0xfffffffe)
    assert send(backend, late) == {'success': False, 'errmsg': 'NonFinal'}
    assert chain.rpc.nonce(backend.address) == n      # no gas spent on either


def test_gas_cap(chain, backend, monkeypatch):
    txid, _ = deposit(chain, backend)
    tx = spend(backend, txid, 0, 100_000)
    monkeypatch.setattr(eb, 'GAS_CAP', 20_000)
    r = send(backend, tx)
    assert not r['success']
    m = re.fullmatch(r'too large for one EVM tx: (\d+) gas', r['errmsg'])
    assert m and int(m.group(1)) > 20_000
    assert backend.ix.tx(tx.txid_hex()) is None


def test_receipt_makes_a_childs_prevouts_available(chain, backend):
    txid, _ = deposit(chain, backend)
    parent = spend(backend, txid, 0, 100_000)
    assert send(backend, parent)['success']
    # No sync in between: the receipt is ingested before the answer, so a
    # child (a CPFP, say) can be sent at once.
    assert backend.ix.utxo(parent.txid_hex(), 0)['amount'] == 99_000
    assert backend.getutxout(btc.display(txid), 0) == {'amount': None, 'script': None}
    child = spend(backend, parent.txid(), 0, 99_000)
    assert send(backend, child)['success']
    assert backend.getutxout(child.txid_hex(), 0) == {'amount': 98_000, 'script': A.p2wpkh.hex()}
    # and the contract agrees with the index
    assert chain.is_unspent(child.txid(), 0, 98_000, A.p2wpkh, backend.ix.tx(child.txid_hex())['height'])


def test_unmined_send_is_success_and_is_outbid_at_its_nonce(chain, backend, monkeypatch):
    """A send the node took is success even with no receipt in time (failure
    would tell CLN it was never sent). The next send finds the nonce still
    held and replaces it at >= 1.25x the fees: here onchaind's re-signed
    version of the same spend."""
    monkeypatch.setattr(eb, 'RECEIPT_WAIT', 0.3)
    signed = []
    sign_tx = backend.account.sign_tx
    monkeypatch.setattr(backend.account, 'sign_tx', lambda tx: signed.append(tx) or sign_tx(tx))
    txid, _ = deposit(chain, backend)
    first, second = spend(backend, txid, 0, 100_000, fee=1000), spend(backend, txid, 0, 100_000, fee=2000)
    chain.rpc.call('evm_setAutomine', False)
    try:
        assert send(backend, first) == {'success': True, 'errmsg': ''}
        assert backend._unmined is not None and backend.ix.tx(first.txid_hex()) is None
        assert send(backend, second) == {'success': True, 'errmsg': ''}
        assert int(chain.rpc.request('txpool_status')['pending'], 16) == 1      # replaced, not queued behind
        a, b = signed
        assert a['nonce'] == b['nonce']
        assert b['maxFeePerGas'] * 4 >= a['maxFeePerGas'] * 5
        assert b['maxPriorityFeePerGas'] * 4 >= a['maxPriorityFeePerGas'] * 5
        chain.mine()
    finally:
        chain.rpc.call('evm_setAutomine', True)
    chain.mine()
    backend.poll_once()
    assert backend.ix.tx(second.txid_hex()) is not None and backend.ix.tx(first.txid_hex()) is None
    # Once it is mined the next send takes the next nonce, at the network's fees.
    child = spend(backend, second.txid(), 0, 98_000)
    assert send(backend, child)['success'] and backend._unmined is None
    assert signed[-1]['nonce'] == a['nonce'] + 1


def test_node_refusing_the_send_is_failure(chain, backend, monkeypatch):
    txid, _ = deposit(chain, backend)
    tx = spend(backend, txid, 0, 100_000)

    def refuse(raw):
        raise evm.EvmError('eth_sendRawTransaction: JSON-RPC error -32000', -32000)
    monkeypatch.setattr(backend.rpc, 'send_raw', refuse)
    r = send(backend, tx)
    assert r == {'success': False, 'errmsg': 'EVM node: eth_sendRawTransaction: JSON-RPC error -32000'}
    assert backend._unmined is None
    monkeypatch.undo()
    assert send(backend, tx)['success']


class NonceRpc:
    """The EVM node as _send sees it (no anvil): an account nonce, a mempool
    by nonce and receipts by tx hash. mine() mines the mempool in nonce
    order, reorg() takes mined txs back (dropped, as after anvil_reorg)."""

    def __init__(self):
        self.mined, self.pool, self.sent, self.lag = [], {}, [], 0

    def estimate_gas(self, *a, **kw):
        return 100_000

    def fees(self):
        return 10**9, 3 * 10**9

    def nonce(self, address, block='pending'):
        assert block == 'latest'
        return max(len(self.mined) - self.lag, 0)

    def send_raw(self, raw):
        self.sent.append(raw)

    def request(self, method, *params):
        assert method == 'eth_getTransactionReceipt'
        return {'status': '0x1', 'logs': []} if params[0] in self.mined else None

    def reorg(self, n):
        del self.mined[len(self.mined) - n:]


def nonce_backend(tmp_path, monkeypatch, automine=True):
    b = offline_backend(tmp_path)
    rpc, signed = NonceRpc(), []
    b.rpc, b.ix = rpc, type('Ix', (), {'add_receipt': staticmethod(lambda r: [])})()
    b._chain_id = 31337
    monkeypatch.setattr(b, 'chain_id', lambda: 31337)
    sign_tx = b.account.sign_tx

    def sign(tx):
        raw, txhash = sign_tx(tx)
        signed.append(tx)
        rpc.pool[tx['nonce']] = txhash
        while b.automine and len(rpc.mined) in rpc.pool:
            rpc.mined.append(rpc.pool.pop(len(rpc.mined)))
        return raw, txhash
    b.automine = automine
    monkeypatch.setattr(b.account, 'sign_tx', sign)
    monkeypatch.setattr(eb, 'RECEIPT_WAIT', 0.0)
    return b, rpc, signed


def test_reorg_taking_back_a_mined_send_does_not_leave_a_nonce_gap(tmp_path, monkeypatch):
    """Our send at nonce 1 was mined, then an EVM reorg dropped it: the next
    send goes at nonce 1 again (not 2, which could never mine and would hold
    every later send), outbidding the lost one in case it is in a mempool."""
    b, rpc, signed = nonce_backend(tmp_path, monkeypatch)
    to = '0x' + '22' * 20
    for _ in range(2):
        assert b._send(to, b'')[1] is not None
    assert [t['nonce'] for t in signed] == [0, 1] and b._next_nonce == 2
    rpc.reorg(1)
    txhash, receipt = b._send(to, b'')
    assert receipt is not None and signed[-1]['nonce'] == 1
    assert signed[-1]['maxFeePerGas'] * 4 >= signed[1]['maxFeePerGas'] * 5
    assert signed[-1]['maxPriorityFeePerGas'] * 4 >= signed[1]['maxPriorityFeePerGas'] * 5
    assert any('reorg' in m for m in b._log.at('unusual'))
    assert b._send(to, b'')[1] is not None and signed[-1]['nonce'] == 2 and b._unmined is None
    # Two taken back at once: from the chain's nonce again.
    rpc.reorg(2)
    assert b._send(to, b'')[1] is not None and signed[-1]['nonce'] == 1


def test_send_stuck_above_a_reorg_gap_recovers(tmp_path, monkeypatch):
    """The state the old code got into: a send waiting at a nonce above the
    chain's. The next send fills the gap instead of replacing it for ever."""
    b, rpc, signed = nonce_backend(tmp_path, monkeypatch)
    to = '0x' + '22' * 20
    b._send(to, b'')
    rpc.reorg(1)
    b._next_nonce, b._mined, b._unmined = 2, None, (2, 10**9, 3 * 10**9)
    assert b._send(to, b'')[1] is not None and signed[-1]['nonce'] == 0
    assert signed[-1]['maxFeePerGas'] == 3 * 10**9


def test_lagging_node_does_not_reuse_a_mined_nonce(tmp_path, monkeypatch):
    """A node answering a nonce from before our last mined send (whose
    receipt it has) is not a reorg: the next send still takes the next nonce."""
    b, rpc, signed = nonce_backend(tmp_path, monkeypatch)
    to = '0x' + '22' * 20
    b._send(to, b'')
    rpc.lag = 1
    b._send(to, b'')
    assert [t['nonce'] for t in signed] == [0, 1] and not b._log.at('unusual')


# ------------------------------------------------------------ the read methods and the RPCs

def test_read_methods_and_ibd(chain, tmp_path):
    log = Log()
    b = eb.Backend(make_cfg(tmp_path, chain.rpc.url, chain.address), log)
    chain.mine_at(3)
    chain.mine_at(4)                       # `safe` is the block at height 3
    b.connect(retry_for=0)
    ci = b.getchaininfo()
    assert ci['chain'] == 'regtest' and ci['ibd'] is True and ci['blockcount'] == 0
    assert ci['headercount'] == 2          # from the live read at startup, never below the tip
    assert b.getchaininfo_fallback() == dict(ci, ibd=True)
    chain.mine()
    b.poll_once()
    ci = b.getchaininfo()
    assert ci['ibd'] is False and ci['headercount'] == ci['blockcount'] == b.ix.tip() >= 1
    blk = b.getrawblockbyheight(1)
    hdr, txs = btc.parse_block(bytes.fromhex(blk['block']))
    assert btc.display(btc.block_hash(hdr)) == blk['blockhash']
    assert b.getrawblockbyheight(b.ix.tip() + 1) == {'blockhash': None, 'block': None}
    assert b.getrawblockbyheight('x') == {'blockhash': None, 'block': None}
    assert b.getutxout('00' * 32, 0) == {'amount': None, 'script': None}
    assert b.getutxout('nothex', 0) == {'amount': None, 'script': None}
    assert b.estimatefees() == eb.ESTIMATEFEES
    b.ix.close()


def test_deposit_withdraw_status(chain, backend):
    ln = FakeLn({'newaddr': {'p2tr': btc.segwit_address('bcrt', 1, A.xonly)}})
    backend.lnrpc = lambda: ln
    d = backend.deposit(50_000)
    assert d['status'] == 'mined' and d['amount_sat'] == 50_000 and d['address'].startswith('bcrt1p')
    assert backend.ix.utxo(d['txid'], 0) == {'amount': 50_000, 'script': A.p2tr, 'height': d['height']}
    with pytest.raises(eb.UserError, match='P2WPKH or P2TR'):
        backend.deposit(1000, backend.exitaddr(backend.address)['address'])
    # Nor to a witness program the contract can't spend (v2): nothing is sent.
    with pytest.raises(eb.UserError, match='P2WPKH or P2TR'):
        backend.deposit(1000, btc.segwit_address('bcrt', 2, bytes(32)))
    with pytest.raises(eb.UserError, match='at least 1 sat'):
        backend.deposit(0)
    with pytest.raises(eb.UserError, match='nothing to withdraw'):
        backend.withdraw()
    # Pay an exit to our own address, then withdraw it.
    txid, _ = deposit(chain, backend)
    tx = spend(backend, txid, 0, 100_000, out_script=btc.exit_script(backend.address), fee=500)
    assert send(backend, tx)['success']
    assert backend.status()['withdrawable_wei'] == 100_000 * SAT    # 99,500 exit + 500 fee to the submitter
    before = int(chain.rpc.request('eth_getBalance', backend.address, 'latest'), 16)
    w = backend.withdraw()
    assert w['status'] == 'mined' and w['amount_wei'] == 100_000 * SAT
    rc = chain.rpc.request('eth_getTransactionReceipt', w['evm_tx'])
    after = int(chain.rpc.request('eth_getBalance', backend.address, 'latest'), 16)
    assert after - before == 100_000 * SAT - int(rc['gasUsed'], 16) * int(rc['effectiveGasPrice'], 16)
    s = backend.status()
    for k in ('contract', 'chain_id', 'interval', 'eth_address', 'balance_wei', 'withdrawable_wei', 'tip',
              'current_height', 'lag', 'alarms', 'opens_refused'):
        assert k in s
    assert s['withdrawable_wei'] == 0 and s['balance_wei'] == after and s['opens_refused'] is None
    # Every HTTP request is counted by method (credit accounting).
    assert s['rpc_calls'].get('eth_sendRawTransaction', 0) >= 3 and s['rpc_calls'].get('eth_call', 0) >= 1
    assert backend.status()['rpc_calls']['eth_getBalance'] > s['rpc_calls']['eth_getBalance']
    assert backend.exitaddr(backend.address)['address'].startswith('bcrt1s')
    with pytest.raises(eb.UserError, match='20-byte'):
        backend.exitaddr('0x12')


def test_status_cached_and_funds_reads(chain, backend):
    """evm-status cached=true talks to no node (for pollers), and the poll
    re-reads the balances only when they may have changed."""
    backend.refresh_funds(force=True, now=1000.0)

    def calls():
        return sum(backend.rpc.calls.values())
    n = calls()
    s = backend.status(cached=True)
    assert calls() == n and s['cached'] is True and s['balance_wei'] == backend.balance == 10**20
    backend.refresh_funds(now=1000.0 + eb.FUNDS_MAX_AGE - 1)
    assert calls() == n
    backend.refresh_funds(now=1000.0 + eb.FUNDS_MAX_AGE)
    assert calls() == n + 2                         # the balance and withdrawable
    backend.funds_dirty = True                      # as after a send, or a poll that found new logs
    backend.refresh_funds(now=1000.0 + eb.FUNDS_MAX_AGE + 1)
    assert calls() == n + 4 and not backend.funds_dirty
    backend.cfg.min_balance_wei = 10**21            # below the minimum: every poll, to clear the alarm soon
    backend.refresh_funds(now=1000.0 + eb.FUNDS_MAX_AGE + 2)
    assert calls() == n + 6


# ------------------------------------------------------------ hooks

GOOD_CONFIGS = {'watchtime-blocks': {'value_int': 40}, 'cltv-delta': {'value_int': 40},
                'cltv-final': {'value_int': 40}, 'funding-confirms': {'value_int': 1},
                'max-concurrent-htlcs': {'value_int': 30}, 'developer': {'set': True},
                'dev-bitcoind-poll': {'value_int': 1}}
# Real init/node features of this tree's lightningd with --dev-force-features=-63.
GOOD_INFO = {'our_features': {'init': '08a0880a8a59a1', 'node': '88a0880a8a59a1'}}


def features(*bits):
    return '{:x}'.format(sum(1 << b for b in bits))


def test_peer_connected(tmp_path):
    b = offline_backend(tmp_path)
    assert b.peer_connected({'id': '02' * 33, 'features': GOOD_INFO['our_features']['init']}) \
        == {'result': 'continue'}
    assert b.peer_connected({'id': '02' * 33, 'features': features(12, 22)})['result'] == 'continue'
    for f in (features(12, 13, 20, 21), '', None, 'zz'):
        assert b.peer_connected({'id': '02' * 33, 'features': f})['result'] == 'disconnect'


def open_payload(**kw):
    p = {'id': '02' * 33, 'funding_msat': 10**9, 'max_accepted_htlcs': 30, 'to_self_delay': 40,
         'channel_type': {'bits': [12, 22], 'names': ['static_remotekey/even', 'anchors/even']}}
    p.update(kw)
    return p


def test_openchannel_hooks(tmp_path):
    b = offline_backend(tmp_path)
    assert b.openchannel(open_payload()) == {'result': 'continue'}
    assert b.openchannel(open_payload(channel_type={'bits': [12, 22, 46, 50]})) == {'result': 'continue'}
    for bad in (open_payload(channel_type={'bits': [12]}), open_payload(max_accepted_htlcs=31),
                open_payload(channel_type=None), open_payload(max_accepted_htlcs='x')):
        r = b.openchannel(bad)
        assert r['result'] == 'reject' and r['error_message'], bad
    # Dual funding is refused whatever it offers.
    r = b.openchannel2(open_payload())
    assert r['result'] == 'reject' and 'dual-funded' in r['error_message']
    b.balance = 10**15                          # below evm-min-balance
    assert 'evm-min-balance' in b.openchannel(open_payload())['error_message']
    b.balance = None
    assert 'unknown' in b.openchannel(open_payload())['error_message']
    b.balance = 10**18
    b.apply_option_check({'developer': {'set': True}}, {})
    assert 'SPEC 5.6' in b.openchannel(open_payload())['error_message']


# ------------------------------------------------------------ the option check (5.6)

def test_option_check():
    assert eb.check_options(GOOD_CONFIGS, GOOD_INFO, 2, 31337) == []
    # --chain-hash: optional, but if given it must be this contract's.
    contract = '0x' + 'aB' * 20
    right = eb.chain_hash_for(31337, contract)
    assert right == eb.chain_hash_for(31337, contract.lower()) != eb.chain_hash_for(1, contract)
    assert eb.check_options({**GOOD_CONFIGS, 'chain-hash': {'value_str': right}}, GOOD_INFO, 2, 31337, contract) == []
    probs = eb.check_options({**GOOD_CONFIGS, 'chain-hash': {'value_str': '00' * 32}}, GOOD_INFO, 2, 31337, contract)
    assert len(probs) == 1 and 'chain-hash' in probs[0]
    regtest = {'watchtime-blocks': {'value_int': 6}, 'cltv-delta': {'value_int': 6},
               'cltv-final': {'value_int': 10}, 'funding-confirms': {'value_int': 1},
               'max-concurrent-htlcs': {'value_int': 483}}
    probs = eb.check_options(regtest, {'our_features': {'init': features(12, 23, 63)}}, 2, 31337)
    text = '\n'.join(probs)
    for want in ('watchtime-blocks', 'cltv-delta', 'cltv-final', 'max-concurrent-htlcs', '--developer',
                 'dev-bitcoind-poll', 'splicing'):
        assert want in text, want
    assert 'funding-confirms' not in text
    c = dict(GOOD_CONFIGS, **{'dev-bitcoind-poll': {'value_int': 2}})
    assert len(eb.check_options(c, GOOD_INFO, 2, 31337)) == 1            # anvil needs --dev-bitcoind-poll=1
    # Wall-clock time: on anvil at INTERVAL 1, 40 blocks are 40 s < 80 s.
    assert len(eb.check_options(GOOD_CONFIGS, GOOD_INFO, 1, 31337)) == 3
    assert eb.option_minimums(1, 31337)[0]['watchtime-blocks'] == 80
    # Base Sepolia (INTERVAL 60): 24 h and 2.4 h; CLN's default 30 s poll is fine.
    sep = {'watchtime-blocks': {'value_int': 1440}, 'cltv-delta': {'value_int': 144},
           'cltv-final': {'value_int': 144}, 'funding-confirms': {'value_int': 3},
           'max-concurrent-htlcs': {'value_int': 30}, 'developer': {'set': True}}
    assert eb.check_options(sep, GOOD_INFO, 60, 84532) == []
    assert eb.check_options(dict(sep, **{'funding-confirms': {'value_int': 2}}), GOOD_INFO, 60, 84532) != []
    # The anvil column only on chain id 31337: anvil's values fail on any other chain,
    # even at INTERVAL 2 (where a day is 43,200 blocks and the poll must be 1 s).
    probs = eb.check_options(GOOD_CONFIGS, GOOD_INFO, 2, 84532)
    assert len(probs) == 4 and '43200' in probs[0]
    assert eb.option_minimums(2, 1)[1] == 1 and eb.option_minimums(60, 1)[1] == 30


def test_option_check_refuses_opens_and_logs_broken(tmp_path):
    log = Log()
    ln = FakeLn({'listconfigs': {'configs': {}}, 'getinfo': {'our_features': {}}})
    b = offline_backend(tmp_path, ln=ln, log=log, checked=False)
    assert 'not checked' in b.open_refusal()
    b._option_check_loop()           # what the background thread runs
    assert b.options_checked and b.option_problems
    assert len(log.at('broken')) == len(b.option_problems)
    assert 'SPEC 5.6' in b.open_refusal()
    assert b.openchannel(open_payload())['result'] == 'reject'


# ------------------------------------------------------------ alarms (5.5)

class FakeIx:
    chain_id = 31337

    def __init__(self):
        self.lag_v, self.tag, self.wall = 1, (100, 0), 0

    def current_height(self):
        return 100 + self.lag_v

    def tip(self):
        return 100

    def height_at(self, ts):
        return self.wall

    def tag_block(self):
        return self.tag


def test_alarms(tmp_path):
    log = Log()
    b = offline_backend(tmp_path, log=log)
    b.ix = FakeIx()
    now = 1000.0
    assert b.check_alarms(now) == {}
    assert b.margin() == 20                       # min(40, 41 // 2, 41 // 2)
    b.ix.lag_v = 6                                # 6 + 1 s / 2 s = 6.5 <= 20 / 3
    assert b.check_alarms(now) == {}
    b.ix.lag_v = 7
    assert set(b.check_alarms(now + 1)) == {'lag'}
    assert len(log.at('broken')) == 1
    b.check_alarms(now + 2)                       # not repeated at once
    assert len(log.at('broken')) == 1
    b.ix.tag = (100.5, 0)                         # (the tag moves meanwhile)
    b.check_alarms(now + 700)                     # but every 10 minutes
    assert len(log.at('broken')) == 2
    b.ix.lag_v = 1
    b.check_alarms(now + 701)
    assert 'alarm cleared: lag' in log.at('info')[-1]
    # An outage: no sync, but the wall-clock height runs on (SPEC 3.1).
    b.ix.wall = 110
    assert 'lag' in b.check_alarms(now + 701.5)
    b.ix.wall = 0
    b.check_alarms(now + 701.6)
    # The tag not advancing for 10 x INTERVAL (anvil: 20 s), then advancing.
    t = now + 702
    b.check_alarms(t)
    assert 'tag' in b.check_alarms(t + 21)
    b.ix.tag = (101, 2)
    assert 'tag' not in b.check_alarms(t + 22)
    # Balance below evm-min-balance.
    b.balance = 10**15
    assert 'balance' in b.check_alarms(t + 23)
    b.balance = 10**18
    # An index-sync error lasting more than 5 x INTERVAL.
    b._sync_failed('eth_getLogs: URLError', t + 24)
    assert 'sync' not in b.check_alarms(t + 30)
    assert 'sync' in b.check_alarms(t + 35)
    assert any('eth_getLogs: URLError' in m for m in log.at('broken'))


def test_polls_sit_on_the_wall_clock(tmp_path):
    """Two nodes started at different times poll in the same part of each
    period (each a fixed offset of at most 30 s after the multiples of
    evm-poll), so they disagree about the tip for that long at most."""
    b = offline_backend(tmp_path)
    b.cfg.poll = 180
    off = min(eb.POLL_SPREAD, 45) * int(b.address[-4:], 16) / 65536.0
    assert 0 <= off < 30
    for started in (1_000_000.0, 1_000_047.3, 1_000_161.9):
        at = started + b.poll_wait(started)
        assert abs((at - off) % 180) < 1e-6 or abs((at - off) % 180 - 180) < 1e-6
        assert 18 <= at - started <= 198
    # Just after its slot (the poll took a moment): the next slot, not at once.
    slot = 180 * 5556 + off
    assert abs(b.poll_wait(slot + 0.2) - 179.8) < 1e-6
    assert abs(b.poll_wait(slot - 30) - 30) < 1e-6
    # A failed sync is tried again after 15 s, 30 s, 60 s..., never later
    # than the regular poll.
    assert b.poll_wait(slot + 0.2, failures=1) == 18          # (at least a tenth of a poll)
    assert b.poll_wait(slot + 0.2, failures=2) == 30
    assert b.poll_wait(slot + 0.2, failures=3) == 60
    assert abs(b.poll_wait(slot + 0.2, failures=9) - 179.8) < 1e-6
    assert b.poll_wait(slot - 10, failures=1) == 18
    # anvil's 1 s poll: never a busy loop, never more than a poll and a bit.
    b.cfg.poll = 1
    assert all(0.1 <= b.poll_wait(1_000_000 + i * 0.137, failures=f) <= 1.1 for i in range(50) for f in (0, 1, 5))


def test_poll_reports_a_failing_node_then_recovers(chain, backend):
    good = backend.rpc
    backend.rpc = backend.ix.rpc = evm.EvmRpc('http://127.0.0.1:{}'.format(free_port()), timeout=1)
    backend.poll_once(now=1000.0)
    assert backend.sync_error_since == 1000.0 and 'eth_getBlockByNumber' in backend.last_sync_error
    backend.poll_once(now=1000.0 + 5 * INTERVAL + 1)
    assert 'sync' in backend.alarms and 'sync_error' in backend.status(cached=True)
    backend.rpc = backend.ix.rpc = good
    chain.mine()
    backend.poll_once()
    assert backend.sync_error_since is None and 'sync' not in backend.alarms


# ------------------------------------------------------------ options, keys and secrets (5.1)

def options(**kw):
    o = {'evm-rpc': 'http://127.0.0.1:8545', 'evm-contract': '0x' + '22' * 20, 'evm-key-file': None,
         'evm-confirm': 'safe', 'evm-poll': '45', 'evm-min-balance': '0.01'}
    o.update(kw)
    return o.get


def test_config_and_key_file(tmp_path):
    log = Log()
    cfg = eb.Config.from_options(options(), str(tmp_path), {}, log)
    path = tmp_path / 'evm-key'
    assert cfg.key_file == str(path) and cfg.poll == 45 and cfg.min_balance_wei == 10**16 and cfg.confirm == 'safe'
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert evm.unhex(path.read_text().strip()) == cfg.key
    assert cfg.key.hex() not in log.text()
    assert eb.Config.from_options(options(), str(tmp_path), {}, log).key == cfg.key     # reused
    os.chmod(path, 0o644)
    eb.Config.from_options(options(), str(tmp_path), {}, log)
    assert any('chmod 600' in m for m in log.at('broken'))
    (tmp_path / 'bad').write_text('not a key 0123')
    with pytest.raises(eb.ConfigError) as e:
        eb.Config.from_options(options(**{'evm-key-file': 'bad'}), str(tmp_path), {}, log)
    assert '0123' not in str(e.value)
    for bad in ({'evm-confirm': 'finalized'}, {'evm-poll': '0'}, {'evm-poll': 'x'}, {'evm-min-balance': '-1'},
                {'evm-contract': '0x12'}, {'evm-rpc': 'file:///etc/passwd'}, {'evm-rpc': None}):
        with pytest.raises(eb.ConfigError):
            eb.Config.from_options(options(**bad), str(tmp_path), {}, log)


SECRET = 'S3cr3tInfuraKey0123456789abcdef'


def test_infura_key_substitution(tmp_path):
    url = 'https://base-sepolia.infura.io/v3/${INFURA_API_KEY}'
    with pytest.raises(eb.ConfigError) as e:
        eb.Config.from_options(options(**{'evm-rpc': url}), str(tmp_path), {}, None)
    assert 'INFURA_API_KEY' in str(e.value)
    cfg = eb.Config.from_options(options(**{'evm-rpc': url}), str(tmp_path), {'INFURA_API_KEY': SECRET}, None)
    assert cfg.rpc_url == 'https://base-sepolia.infura.io/v3/' + SECRET
    assert SECRET in cfg.secrets and cfg.rpc_url in cfg.secrets


def test_secrets_never_logged_unreachable(tmp_path):
    log = Log()
    port = free_port()                # a port nothing listens on
    url = 'http://127.0.0.1:{}/v3/${{INFURA_API_KEY}}'.format(port)
    cfg = eb.Config.from_options(options(**{'evm-rpc': url}), str(tmp_path), {'INFURA_API_KEY': SECRET}, log)
    b = eb.Backend(cfg, log)
    with pytest.raises(evm.EvmError) as e:
        b.connect(retry_for=1.5)
    for text in (str(e.value), repr(e.value), log.text()):
        assert SECRET not in text and cfg.key.hex() not in text and str(port) + '/v3' not in text
    assert log.lines                  # it did log the retries


def test_secrets_never_logged_on_anvil(chain, tmp_path):
    log = Log()
    url = chain.rpc.url + '/?key=${INFURA_API_KEY}'
    cfg = eb.Config.from_options(options(**{'evm-rpc': url, 'evm-contract': chain.address, 'evm-poll': '1'}),
                                 str(tmp_path), {'INFURA_API_KEY': SECRET}, log)
    b = eb.Backend(cfg, log)
    chain.rpc.call('anvil_setBalance', b.address, evm.qty(10**20))
    chain.mine_at(1)
    b.connect(retry_for=0)
    b.apply_option_check(GOOD_CONFIGS, GOOD_INFO)
    try:
        txid, _ = deposit(chain, b)
        txid2, _ = deposit(chain, b)
        results = [send(b, spend(b, txid, 0, 100_000, locktime=10**6, sequence=0)),
                   send(b, spend(b, txid, 0, 100_000)),
                   b.sendrawtransaction('00')]
        chain.mine()
        b.poll_once()
        results.append(b.status())
        # The node goes away: sends, polls and evm-status fail without the URL.
        b.rpc = b.ix.rpc = evm.EvmRpc('http://127.0.0.1:{}/{}'.format(free_port(), SECRET), timeout=1)
        results.append(send(b, spend(b, txid2, 0, 100_000, fee=7)))
        b.poll_once()
        results.append(b.status())
        text = log.text() + json.dumps(results, default=str)
        assert SECRET not in text and cfg.key.hex() not in text and cfg.key.hex()[2:] not in text
        assert results[1]['success'] and not results[0]['success']
        assert results[4]['errmsg'].startswith('EVM node: eth_estimateGas') and 'balance_error' in results[5]
    finally:
        b.stop()
        b.ix.close()


def test_scrub_is_applied_to_every_log_line(tmp_path):
    log = Log()
    b = eb.Backend(make_cfg(tmp_path, url='http://h/' + SECRET, secrets=[SECRET]), log)
    b.log('broken', 'leak http://h/{} {}'.format(SECRET, b.cfg.key.hex()))
    assert SECRET not in log.text() and b.cfg.key.hex() not in log.text() and '<redacted>' in log.text()
