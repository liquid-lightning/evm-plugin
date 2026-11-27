#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The Bitcoin backend plugin of SPEC 5, minimal build: Core Lightning runs
with `--network=regtest --disable-plugin=bcli --plugin=evmbackend.py` and sees
the UtxoChain contract as a chain of Bitcoin blocks.

    lightningd --network=regtest --disable-plugin=bcli \\
        --plugin=contrib/evmchan/evmbackend.py \\
        --evm-rpc=<url> --evm-contract=<address> [SPEC 5.6 options]

What it does (section numbers are SPEC's):
- 5.1 options; the node's own ETH key (evm-key-file, created 0600).
- 5.2 the index (evmindex.Index), synced by a poll thread every evm-poll s.
- 5.3 bcli's five methods. The read methods answer from the index only.
  sendrawtransaction turns the tx into a `submit` call: checked first with
  eth_estimateGas (a revert costs no gas and is answered as failure, with
  the contract error's name), then signed, sent, and its receipt waited for
  up to RECEIPT_WAIT s. One send at a time, from the chain's own nonce.
- 5.4 hooks: peers without anchors are disconnected, inbound opens must be
  anchors_zero_fee_htlc_tx with at most 30 HTLCs, dual funding is refused.
- 5.5 evm-deposit, evm-exitaddr, evm-withdraw, evm-status, and alarms.
- 4.6 token mode: on a UtxoChainToken (TOKEN() answers) amounts are token
  units (UNITS_PER_SAT per sat), evm-deposit approves the token first, and
  gas is still paid in ETH.
- 5.6 the CLN option check, from a background thread after init.

This build is for testnets. It leaves out of SPEC 5: proving the node's
answers against the contract's logHash, index repair and snapshots (5.2);
tracking sends across restarts, fee replacement on a timer and re-sending
after an EVM reorg (5.3: lightningd rebroadcasts what isn't mined, and a send
that finds its nonce still held by the last one outbids it); the peer
identity handshake, the checks on our own open commands, and the HTLC cap on
forwards (5.4: every node is expected to run with the 5.6 options, on the
same contract); evm-txinfo and evm-snapshot (5.5).

No backend method ever returns a JSON-RPC error (lightningd treats one as
fatal): every failure is an answer inside `result`.

Threads: pyln's main loop (the read methods and hooks; never on the network),
the poll thread (Index.sync, balances, alarms), the option-check thread
(once), and one short-lived thread per send or RPC of ours.

Secrets (5.1): the RPC URL (and the Infura key in it) and the ETH key never
reach a log or an error. evm.EvmError carries only the method, the error's
type and its code, and every message goes through scrub() as well.

The logic is in class Backend, which has no pyln dependency (the unit tests
drive it directly); main() wires it to pyln.
"""
import decimal
import hashlib
import os
import stat
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import coincurve   # noqa: E402

import btc         # noqa: E402
import evm         # noqa: E402
import evmindex    # noqa: E402

# ------------------------------------------------------------ constants

SAT_WEI = 10**10                      # SPEC 2: 1 sat = 10 gwei (in token mode, UNITS_PER_SAT units)
GAS_CAP = 12_000_000                  # SPEC 4.5 / 5.3: refuse a submit estimated above this
GAS_LIMIT_MAX = 16_000_000            # below EIP-7825's 16,777,216 per-tx cap
MAX_HTLCS = 30                        # SPEC 5.4 / 5.6
RECEIPT_WAIT = 30.0                   # seconds a send waits for its receipt
CONNECT_RETRY = 60                    # seconds init keeps trying the EVM node (bcli's default)
FUNDS_MAX_AGE = 300                   # seconds between reads of the key's balances while nothing changed
POLL_SPREAD = 30.0                    # seconds over which nodes' polls are spread within a period (poll_wait)
POLL_RETRY = 15.0                     # seconds before a failed sync is tried again (doubling)
CLN_DEFAULT_POLL = 30                 # lightningd polls the backend every 30 s without --dev-bitcoind-poll
SUBMIT_SIG = 'submit(bytes,(uint64,bytes,uint32)[])'
SUBMIT_TYPES = ['bytes', '(uint64,bytes,uint32)[]']

ESTIMATEFEES = {'feerate_floor': 1000,
                'feerates': [{'blocks': 2, 'feerate': 5000}, {'blocks': 6, 'feerate': 4000},
                             {'blocks': 12, 'feerate': 3000}, {'blocks': 100, 'feerate': 1000}]}

# Every custom error of contracts/evm/src/Errors.sol by selector, plus Solidity's
# Error(string) and Panic(uint256). Embedded so the plugin never depends on
# build output; tests/test_backend.py checks it against Errors.sol and the ABI.
ERRORS = {
    '085de625': 'TooEarly()',
    'ab8c720a': 'BadInterval()',
    'd2169344': 'HeightOverflow()',
    '259e8a16': 'BadDepositValue()',
    'e68ef9b9': 'BadDepositScript()',
    'd0d04f60': 'NothingToWithdraw()',
    '750b219c': 'WithdrawFailed()',
    '7401d931': 'BadToken()',
    'd3c6b55e': 'BadUnitsPerSat()',
    '045c4b02': 'TokenTransferFailed()',
    '570883e5': 'TokenAmountMismatch()',
    'ab143c06': 'Reentrancy()',
    'cf3c5481': 'TxTooLarge()',
    'cdda5c84': 'Truncated()',
    'd47a5751': 'NonCanonicalCompactSize()',
    'd4c08c19': 'BadSegwitFlag()',
    '0b858f8d': 'EmptyWitnesses()',
    '315fd5b2': 'NoInputs()',
    '9db7282b': 'NoOutputs()',
    '1054cca6': 'TrailingBytes()',
    '752a077a': 'PrevoutCountMismatch()',
    '614e7c97': 'ScriptSigNotEmpty(uint256)',
    '3f785f48': 'NullPrevout(uint256)',
    '73f9ec56': 'DuplicateInput(uint256)',
    'cd7f81f9': 'UnknownUtxo(uint256)',
    '06250401': 'AmountTooLarge()',
    'af548d92': 'OutputsExceedInputs()',
    '9c2f1072': 'TooManySigops()',
    'c97a0f02': 'NonFinal()',
    'a3b7efd7': 'TimeRelativeLockUnsupported(uint256)',
    '4c4259a3': 'RelativeLockNotMet(uint256)',
    'd2d4a3fc': 'UnsupportedScriptPubKey(uint256)',
    'e644bc14': 'BadWitness(uint256)',
    '2f6248ab': 'KeyHashMismatch(uint256)',
    '224c9181': 'WitnessScriptMismatch(uint256)',
    '022f31a0': 'UnknownWitnessScript(uint256)',
    '47bdd76e': 'BadPreimage(uint256)',
    '55905e4e': 'CsvNotMet(uint256)',
    'cd1e5411': 'CltvNotMet(uint256)',
    '67f58716': 'BadSignatureEncoding(uint256)',
    'a1c97319': 'BadSignature(uint256)',
    'd212a85f': 'BadPublicKey(uint256)',
    '6c3def5b': 'NoMatchingOutput(uint256)',
    '08c379a0': 'Error(string)',
    '4e487b71': 'Panic(uint256)',
}

# SPEC 5.4: anchors_zero_fee_htlc_tx (22) with static_remotekey (12), and
# optionally scid_alias (46) and zeroconf (50).
CTYPE_REQUIRED = frozenset((12, 22))
CTYPE_ALLOWED = frozenset((12, 22, 46, 50))
ANCHOR_BITS = (22, 23)
SPLICE_BITS = (62, 63)

# SPEC 5.6 (draft 5): minimums in wall-clock seconds; the anvil column only
# on chain id 31337.
ANVIL_CHAIN_ID = 31337
ANVIL_SECONDS = {'watchtime-blocks': 80, 'cltv-delta': 80, 'cltv-final': 80}
PUBLIC_SECONDS = {'watchtime-blocks': 24 * 3600, 'cltv-delta': 8640, 'cltv-final': 8640}


class ConfigError(Exception):
    """Bad options or key file. The text never holds the URL or the key."""


class UserError(Exception):
    """A message for the caller of one of our RPCs, written by us (never
    holding any part of a node's reply)."""


# ------------------------------------------------------------ small helpers

def ok():
    return {'success': True, 'errmsg': ''}


def fail(msg):
    return {'success': False, 'errmsg': msg}


def scrub_text(text, secrets):
    text = str(text)
    for s in secrets:
        if s:
            text = text.replace(s, '<redacted>')
    return text


def feature_set(hexstr, bit):
    """True if feature `bit` is set in a hex feature field (big-endian bit
    field: bit 0 is the low bit of the last byte)."""
    if not hexstr:
        return False
    return bool((int(hexstr, 16) >> bit) & 1)


def ctype_problem(bits):
    """None if a channel_type (list of bit numbers) is one SPEC 5.4 allows,
    else why not."""
    if not isinstance(bits, list) or not all(isinstance(b, int) and not isinstance(b, bool) for b in bits):
        return 'channel_type must be a list of feature bits'
    s = set(bits)
    if not CTYPE_REQUIRED <= s or not s <= CTYPE_ALLOWED:
        return ('channel_type {} is not allowed on this chain: only anchors_zero_fee_htlc_tx (22) with '
                'static_remotekey (12), optionally scid_alias (46) and zeroconf (50)'.format(sorted(s)))
    return None


def is_revert(err):
    """True if an evm.EvmError is the call reverting, not the node failing."""
    return err.data is not None or err.code == 3


def revert_reason(err):
    """The contract error a failed eth_call/eth_estimateGas reverted with, as
    'Name' or 'Name(arg)' (e.g. 'NonFinal', 'BadSignature(1)'), or a generic
    description. Only selectors and decoded arguments: nothing else of the
    node's reply."""
    data = getattr(err, 'data', None)
    for _ in range(3):        # some nodes nest it: {data: {data: '0x..'}}
        if isinstance(data, dict):
            data = data.get('data')
    if not isinstance(data, str) or not data.startswith('0x'):
        if getattr(err, 'code', None) == 3:
            return 'reverted'
        return str(err)
    try:
        b = evm.unhex(data)
    except ValueError:
        return 'reverted'
    if len(b) < 4:
        return 'reverted'
    sig = ERRORS.get(b[:4].hex())
    if sig is None:
        return 'reverted with an unknown error'
    name, types = sig.split('(', 1)
    types = [t for t in types[:-1].split(',') if t]
    if not types or name == 'Error':
        return name     # Error(string)'s text is the node's: never copied
    try:
        args = evm.abi_decode(types, b[4:])
    except ValueError:
        return name
    if name == 'Panic':
        return 'Panic(0x{:x})'.format(args[0])
    return '{}({})'.format(name, ','.join(str(a) for a in args))


# ------------------------------------------------------------ options (5.1) and the key file

class Config:
    def __init__(self, rpc_url, contract, key, key_file, confirm, poll, min_balance_wei, lightning_dir,
                 secrets=()):
        self.rpc_url, self.contract, self.key, self.key_file = rpc_url, contract, key, key_file
        self.confirm, self.poll, self.min_balance_wei = confirm, poll, min_balance_wei
        self.lightning_dir = lightning_dir
        self.secrets = [s for s in secrets if s]

    @classmethod
    def from_options(cls, get_option, lightning_dir, env, log=None):
        """From the plugin's options (get_option(name)) and the environment.
        Creates the key file if it doesn't exist. Raises ConfigError."""
        url = get_option('evm-rpc')
        if not url:
            raise ConfigError('--evm-rpc is required')
        secrets = []
        if '${INFURA_API_KEY}' in url:
            k = env.get('INFURA_API_KEY')
            if not k:
                raise ConfigError('--evm-rpc contains ${INFURA_API_KEY} but INFURA_API_KEY is not set')
            secrets.append(k)
            url = url.replace('${INFURA_API_KEY}', k)
        if not (url.startswith('http://') or url.startswith('https://')):
            raise ConfigError('--evm-rpc must be an http:// or https:// URL')
        secrets.append(url)
        contract = get_option('evm-contract')
        try:
            contract = evm.checksum_address(contract or '')
        except ValueError:
            raise ConfigError('--evm-contract must be a 20-byte hex address') from None
        confirm = get_option('evm-confirm') or 'safe'
        if confirm not in evmindex.TAGS:
            raise ConfigError('--evm-confirm must be safe or latest')
        try:
            poll = float(get_option('evm-poll'))
        except (TypeError, ValueError):
            raise ConfigError('--evm-poll must be a number of seconds') from None
        if not 0 < poll <= 3600:
            raise ConfigError('--evm-poll must be between 0 and 3600 seconds')
        try:
            min_balance = decimal.Decimal(str(get_option('evm-min-balance')))
            if not min_balance.is_finite() or min_balance < 0:
                raise ValueError
            min_balance_wei = int(min_balance * 10**18)
        except (ValueError, ArithmeticError):
            raise ConfigError('--evm-min-balance must be a non-negative amount of ETH') from None
        key_file = get_option('evm-key-file') or os.path.join(lightning_dir, 'evm-key')
        key_file = os.path.join(lightning_dir, key_file)   # relative to the lightning dir
        key = load_or_create_key(key_file, log)
        secrets.append(key.hex())
        return cls(url, contract, key, key_file, confirm, poll, min_balance_wei, lightning_dir, secrets)


def load_or_create_key(path, log=None):
    """The 32-byte ETH key in `path` (hex), created with mode 0600 if the
    file doesn't exist. Raises ConfigError (never with the key in it)."""
    log = log or (lambda level, msg: None)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            st = os.stat(path)
            with open(path) as f:
                text = f.read().strip()
        except OSError as e:
            raise ConfigError('cannot read evm-key-file ({})'.format(type(e).__name__)) from None
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            log('broken', 'evm-key-file {} is accessible by group or others: chmod 600 it'.format(path))
        try:
            key = evm.unhex(text)
            if len(key) != 32:
                raise ValueError
            coincurve.PrivateKey(key)
        except Exception:
            raise ConfigError('evm-key-file {} does not hold a valid 32-byte hex key'.format(path)) from None
        return key
    except OSError as e:
        raise ConfigError('cannot create evm-key-file {} ({})'.format(path, type(e).__name__)) from None
    while True:
        key = os.urandom(32)
        try:
            coincurve.PrivateKey(key)
            break
        except Exception:
            continue
    with os.fdopen(fd, 'w') as f:
        f.write('0x' + key.hex() + '\n')
        f.flush()
        os.fsync(f.fileno())
    log('info', 'created a new EVM key in {} for {}: fund it to pay for gas'.format(
        path, evm.Account(key).address))
    return key


# ------------------------------------------------------------ the CLN option check (5.6)

def option_minimums(interval, chain_id):
    """SPEC 5.6 (draft 5): the minimums as ({option: blocks}, most seconds
    lightningd may poll). They are wall-clock times divided by INTERVAL,
    rounded up; the anvil column only on chain id 31337."""
    anvil = chain_id == ANVIL_CHAIN_ID
    secs = ANVIL_SECONDS if anvil else PUBLIC_SECONDS
    mins = {k: -(-v // interval) for k, v in secs.items()}
    mins['funding-confirms'] = 1 if anvil else 3
    poll = 1 if anvil else max(1, interval / 2.0)
    return mins, poll


def _config_value(configs, name):
    c = configs.get(name)
    if not isinstance(c, dict):
        return None
    for k in ('value_int', 'value_bool', 'value_str', 'value_msat'):
        if k in c:
            return c[k]
    if 'set' in c:
        return c['set']
    return None


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def chain_hash_for(chain_id, contract):
    """The chain hash of this contract's network, for lightningd's
    --chain-hash: nodes started with it take only each other for peers
    (not Bitcoin regtest nodes, nor nodes on another contract)."""
    return hashlib.sha256('evm:{}:{}'.format(chain_id, contract.lower()).encode()).hexdigest()


def check_options(configs, info, interval, chain_id, contract=None):
    """SPEC 5.6: the problems with lightningd's options (`listconfigs`'s
    'configs' and `getinfo`), [] if none."""
    problems = []
    # --chain-hash is optional (an unmodified lightningd has none), but a
    # wrong one would put this node on another contract's network.
    v = _config_value(configs, 'chain-hash')
    if v is not None and contract is not None and str(v).lower() != chain_hash_for(chain_id, contract):
        problems.append('--chain-hash is not this contract\'s: it should be {}'.format(
            chain_hash_for(chain_id, contract)))
    mins, most_poll = option_minimums(interval, chain_id)
    for name, need in mins.items():
        v = _config_value(configs, name)
        if not _is_int(v) or v < need:
            problems.append('--{} is {}, needs at least {} (INTERVAL {} s{})'.format(
                name, v, need, interval, ', anvil' if chain_id == ANVIL_CHAIN_ID else ''))
    v = _config_value(configs, 'max-concurrent-htlcs')
    if not _is_int(v) or v > MAX_HTLCS:
        problems.append('--max-concurrent-htlcs is {}, needs at most {}'.format(v, MAX_HTLCS))
    dev = _config_value(configs, 'developer') is True
    if not dev:
        problems.append('--developer is not set (needed for --dev-force-features=-63)')
    poll = cln_poll_seconds(configs)
    if poll > most_poll:
        problems.append('lightningd polls the backend every {} s, needs at most {:g} s (--dev-bitcoind-poll)'
                        .format(poll, most_poll))
    feats = (info or {}).get('our_features') or {}
    for kind in ('init', 'node'):
        try:
            on = [b for b in SPLICE_BITS if feature_set(feats.get(kind), b)]
        except (TypeError, ValueError):
            on = ['?']
        if on:
            problems.append('splicing is on ({} feature bit {}): needs --dev-force-features=-63'
                            .format(kind, on[0]))
    return problems


def cln_poll_seconds(configs):
    if _config_value(configs, 'developer') is True:
        v = _config_value(configs, 'dev-bitcoind-poll')
        if _is_int(v):
            return v
    return CLN_DEFAULT_POLL


# ------------------------------------------------------------ the backend

class Backend:
    """Everything but the pyln glue. log(level, message) with level
    'broken', 'unusual', 'info' or 'debug'; lnrpc() returns an object with
    .call(method, params) talking to lightningd (used only after init, from
    background threads)."""

    def __init__(self, cfg, log, lnrpc=None):
        self.cfg = cfg
        self._log = log
        self.lnrpc = lnrpc
        self.account = evm.Account(cfg.key)
        self.address = self.account.address
        self.contract = cfg.contract
        self.stop_event = threading.Event()
        self.ix = None
        self.rpc = None
        self.interval = None
        self.token = None        # SPEC 4.6: the ERC-20 of a UtxoChainToken; None for ETH
        self.units_per_sat = SAT_WEI
        self.threads = []
        # sending (5.3): one at a time
        self._send_lock = threading.Lock()
        self._next_nonce = 0     # one above the nonce of our last send seen mined
        self._unmined = None     # (nonce, tip, max fee) of our last send while it has no receipt
        self._mined = None       # (EVM tx hash, nonce, tip, max fee) of our last send seen mined
        # option check (5.6)
        self.options_checked = False
        self.option_problems = []
        self.cln_poll = CLN_DEFAULT_POLL
        self.cln_configs = {}
        # the key's funds, and alarms (5.5)
        self.balance = None      # wei
        self.withdrawable = None     # wei, or token units in token mode
        self.token_balance = None    # token units, token mode only
        self.funds_at = 0.0      # time.time() of their last read
        self.funds_dirty = True  # a send or new logs may have changed them
        self.alarms = {}         # name -> {'since', 'logged', 'message'}
        self.started_at = time.time()   # rpc_calls in evm-status count from here
        self.sync_error_since = None
        self.last_sync_error = None
        self.tag_seen = None     # (tag block number, time.time() when it changed)
        self._init_tag_ts = None
        self._last_chaininfo = None
        self._chain_id = None    # for tests without an index

    # -------------------------------------------------------- logging

    def log(self, level, message):
        try:
            self._log(level, scrub_text(message, self.cfg.secrets))
        except Exception:
            pass

    def scrub(self, message):
        return scrub_text(message, self.cfg.secrets)

    # -------------------------------------------------------- startup

    def connect(self, retry_for=CONNECT_RETRY, rpc=None):
        """Opens the index (checking the contract's code and reading its
        immutables), and reads the asset, the tag block and the balances.
        Retries the EVM node for up to retry_for seconds. Never talks to
        lightningd. Raises evm.EvmError or evmindex.EvmIndexError."""
        self.rpc = rpc or evm.EvmRpc(self.cfg.rpc_url, timeout=10)    # init must end well within 120 s
        end = time.monotonic() + retry_for

        def retry(fn):
            while True:
                try:
                    return fn()
                except evm.EvmError as e:
                    if time.monotonic() >= end:
                        raise
                    self.log('unusual', 'EVM node not ready ({}); retrying'.format(e))
                    time.sleep(1)

        def tag_timestamp():
            try:
                return int(self.rpc.block(self.cfg.confirm)['timestamp'], 16)
            except (KeyError, TypeError, ValueError) as e:
                raise evm.EvmError('eth_getBlockByNumber: no {} block ({})'.format(
                    self.cfg.confirm, type(e).__name__)) from None

        self.ix = retry(lambda: evmindex.Index(os.path.join(self.cfg.lightning_dir, 'evmchan.sqlite3'), self.rpc,
                                               self.contract, tag=self.cfg.confirm, log=self.log))
        self.interval = self.ix.interval
        retry(self._read_asset)
        # The tag's timestamp, which getchaininfo needs before the first
        # sync (a new index would otherwise report height 0, and lightningd
        # would exit: "gone backwards").
        self._init_tag_ts = retry(tag_timestamp)
        try:
            self.refresh_funds(force=True)
        except Exception as e:     # balance None refuses opens until a poll reads it
            self.log('unusual', 'balance not read at startup ({})'.format(type(e).__name__))
        self.rpc.timeout = 30
        self.log('info', 'UtxoChain {} on chain {} (INTERVAL {} s, DEPLOY_BLOCK {}); node key {}; tip {}'.format(
            self.contract, self.ix.chain_id, self.interval, self.ix.deploy_block, self.address, self.ix.tip()))
        if self.token is not None:
            self.log('info', 'token mode: ERC-20 {}, {} units per sat'.format(self.token, self.units_per_sat))

    def _read_asset(self):
        """SPEC 4.6: TOKEN() and UNITS_PER_SAT() of a UtxoChainToken. A
        UtxoChain (ETH) has no TOKEN(): the call reverts. Any other failure
        is the node's, and raised (never taken for ETH mode)."""
        def call(name):
            return self.rpc.eth_call(self.contract, evm.selector(name + '()'))
        try:
            ret = call('TOKEN')
        except evm.EvmError as e:
            if not is_revert(e):
                raise
            self.token, self.units_per_sat = None, SAT_WEI
            return
        try:
            token = evm.abi_decode(['address'], ret)[0]
            units = evm.abi_decode(['uint256'], call('UNITS_PER_SAT'))[0]
        except ValueError:
            raise evmindex.EvmIndexError('TOKEN() or UNITS_PER_SAT() returned no value') from None
        if int(token, 16) == 0 or units == 0:
            raise evmindex.EvmIndexError('bad TOKEN() or UNITS_PER_SAT()')
        self.token, self.units_per_sat = token, units

    def start(self):
        for target, name in ((self._poll_loop, 'evm-poll'), (self._option_check_loop, 'evm-options')):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.stop_event.set()

    def chain_id(self):
        return self.ix.chain_id if self.ix is not None else self._chain_id

    # -------------------------------------------------------- the four read methods (5.3)

    def getchaininfo(self):
        tip = self.ix.tip()
        head = tip
        if self.ix.ibd:
            # Until this process has synced: headercount from the latest
            # read of the tag (init's, then each poll's), so a new index
            # file never reports a chain shorter than CLN's.
            tb = self.ix.tag_block()
            ts = tb[1] if tb is not None else self._init_tag_ts
            if ts is not None:
                head = max(self.ix.height_at(ts) - 1, tip, 0)
        r = {'chain': 'regtest', 'headercount': head, 'blockcount': tip, 'ibd': self.ix.ibd}
        self._last_chaininfo = r
        return r

    def getchaininfo_fallback(self):
        r = self._last_chaininfo or {'chain': 'regtest', 'headercount': 0, 'blockcount': 0, 'ibd': True}
        return dict(r, ibd=True)

    def getrawblockbyheight(self, height):
        try:
            b = self.ix.block(int(height))
        except (TypeError, ValueError):
            b = None
        if b is None:
            return {'blockhash': None, 'block': None}
        return {'blockhash': b[0], 'block': b[1].hex()}

    def getutxout(self, txid, vout):
        try:
            u = self.ix.utxo(str(txid), int(vout))
        except (TypeError, ValueError):
            u = None
        if u is None:
            return {'amount': None, 'script': None}
        return {'amount': u['amount'], 'script': u['script'].hex()}

    def estimatefees(self):
        return {'feerate_floor': ESTIMATEFEES['feerate_floor'],
                'feerates': [dict(x) for x in ESTIMATEFEES['feerates']]}

    # -------------------------------------------------------- sending (5.3)

    def sendrawtransaction(self, txhex):
        """Submits a Bitcoin tx to the contract and waits up to RECEIPT_WAIT s
        for it to be mined. Success means the EVM node took it (or it is
        applied already); failure that nothing was sent, with why. Blocks:
        call it off pyln's thread. Never raises."""
        try:
            tx = btc.Tx.parse(bytes.fromhex(txhex))
        except (ValueError, TypeError):
            return fail('the transaction does not parse')
        txid = tx.txid_hex()
        try:
            with self._send_lock:
                if self.ix.tx(txid) is not None:
                    return ok()
                prevouts = self.ix.prevouts(tx)
                if prevouts is None:
                    return fail('missing or spent inputs')
                data = evm.calldata(SUBMIT_SIG, SUBMIT_TYPES, [tx.serialize(), [tuple(x) for x in prevouts]])
                txhash, receipt = self._send(self.contract, data)
        except UserError as e:
            return fail(str(e))
        except evm.EvmError as e:
            return fail('EVM node: {}'.format(self.scrub(e)))     # method, type and code only
        except Exception as e:     # noqa: B902
            self.log('broken', 'sendrawtransaction {}: internal error ({})'.format(txid, type(e).__name__))
            return fail('internal error ({})'.format(type(e).__name__))
        if receipt is not None and int(receipt['status'], 16) != 1:
            self.log('unusual', 'submit of {} reverted on chain (EVM tx {})'.format(txid, txhash))
        return ok()

    def _send(self, to, data, value=0):
        """Signs and sends one transaction from the node key and waits up to
        RECEIPT_WAIT s for its receipt: (EVM tx hash, receipt or None if not
        mined yet). Raises UserError if it would revert or not fit, and
        evm.EvmError if the node didn't take it: nothing was sent then. The
        caller holds _send_lock."""
        try:
            gas = self.rpc.estimate_gas(self.address, to, data, value, block='latest')
        except evm.EvmError as e:
            if not is_revert(e):
                raise
            raise UserError(revert_reason(e)) from None      # e.g. NonFinal: costs no gas
        if gas > GAS_CAP:
            raise UserError('too large for one EVM tx: {} gas'.format(gas))
        nonce = self._nonce()
        tip, max_fee = self.rpc.fees()
        if self._unmined is not None and self._unmined[0] == nonce:
            # Our last send still holds this nonce: this one replaces it,
            # which a node only accepts at higher fees (1.25x).
            tip = max(tip, -(-self._unmined[1] * 5 // 4))
            max_fee = max(max_fee, -(-self._unmined[2] * 5 // 4), tip)
        raw, txhash = self.account.sign_tx({
            'chainId': self.chain_id(), 'nonce': nonce, 'maxPriorityFeePerGas': tip, 'maxFeePerGas': max_fee,
            'gas': min(gas + gas // 5 + 30_000, GAS_LIMIT_MAX), 'to': to, 'value': value, 'data': data})
        self.rpc.send_raw(raw)
        self._unmined = (nonce, tip, max_fee)
        self.funds_dirty = True
        self.log('debug', 'sent EVM tx {} (nonce {}, gas {})'.format(txhash, nonce, gas))
        receipt = self._wait_receipt(txhash)
        if receipt is not None:
            self._unmined, self._next_nonce = None, nonce + 1
            self._mined = (txhash, nonce, tip, max_fee)
            self.ix.add_receipt(receipt)
        return txhash, receipt

    def _nonce(self):
        """The nonce of the next send: the chain's own (`latest`, so that a
        send of ours still unmined is replaced, not queued behind). A node
        that hasn't caught up with our last mined send may still answer one
        too low, hence _next_nonce; but that holds only while that send is
        mined. If an EVM reorg took it back, _next_nonce would leave a gap
        that no send ever fills: then the chain's nonce is right again, and a
        send at the lost one's nonce outbids it (it may be back in the
        mempool). Raises evm.EvmError."""
        latest = self.rpc.nonce(self.address, 'latest')
        if latest < self._next_nonce:
            r = self.rpc.request('eth_getTransactionReceipt', self._mined[0]) if self._mined is not None else None
            if not (isinstance(r, dict) and 'status' in r):
                self.log('unusual', 'our last mined send is no longer in the chain (a reorg): sending from nonce '
                         '{} again, not {}'.format(latest, self._next_nonce))
                if self._mined is not None and self._mined[1] == latest:
                    self._unmined = (latest,) + self._mined[2:]
                elif self._unmined is not None and self._unmined[0] > latest:
                    self._unmined = None     # it sits behind the gap; no longer the holder of our next nonce
                self._next_nonce, self._mined = latest, None
        return max(latest, self._next_nonce)

    def _wait_receipt(self, txhash):
        """The receipt, or None if there is none within RECEIPT_WAIT s (the tx
        was sent all the same: an error here is never a failed send)."""
        end = time.monotonic() + RECEIPT_WAIT
        while not self.stop_event.is_set():
            try:
                r = self.rpc.request('eth_getTransactionReceipt', txhash)
                if isinstance(r, dict) and 'status' in r:
                    return r
            except evm.EvmError:
                pass
            if time.monotonic() >= end:
                break
            self.stop_event.wait(max(0.2, min(1.0, self.interval / 4.0)))
        return None

    # -------------------------------------------------------- polling and alarms (5.2, 5.5)

    def _poll_loop(self):
        failures = 0
        while not self.stop_event.is_set():
            self.poll_once()
            failures = failures + 1 if self.sync_error_since is not None else 0
            self.stop_event.wait(self.poll_wait(failures=failures))

    def poll_wait(self, now=None, failures=0):
        """Seconds until the next poll.

        Polls sit on the wall clock's multiples of evm-poll, plus this key's
        own fixed offset of up to POLL_SPREAD s (at most a quarter of a
        poll), not evm-poll after the last one.  The tip follows the tag
        block's timestamp (SPEC 3.4), and on an L2 `safe` moves in steps of
        minutes: nodes polling at their own times read it before and after a
        step, and report tips that many virtual blocks apart until the later
        one polls again.  A payee then refuses a payment whose expiry the
        payer set from its lower height.  With polls in the same part of
        each period, nodes disagree for the spread at most, not for a
        whole poll.  (Not all in the same second: nodes sharing an API key
        would exceed its rate limit as soon as there are logs to read.)

        After a failed sync (a rate limit, usually) the next try comes
        sooner: POLL_RETRY s, doubling with each failure in a row, never
        later than the regular poll.  Else a node that failed once reports
        the old tip for a whole poll."""
        now = time.time() if now is None else now
        poll = self.cfg.poll
        offset = min(POLL_SPREAD, poll / 4.0) * int(self.address[-4:], 16) / 65536.0
        wait = poll - (now - offset) % poll
        # (Right after a slot, e.g. a poll that took a whole period: the next one.)
        if wait < poll / 10.0:
            wait += poll
        if failures:
            wait = min(wait, max(poll / 10.0, POLL_RETRY * 2 ** min(failures - 1, 6)))
        return wait

    def poll_once(self, now=None):
        try:
            changed = self.ix.sync()
            if changed is not None:
                self.sync_error_since = self.last_sync_error = None
            if changed:
                self.funds_dirty = True      # a new TxApplied may pay out to us
        except evm.EvmError as e:
            self._sync_failed(self.scrub(e), now)
        except Exception as e:
            self._sync_failed(type(e).__name__, now)
            self.log('broken', 'index sync: {}'.format(type(e).__name__))
        try:
            self.refresh_funds()
        except Exception as e:
            self.log('unusual', 'balance: {}'.format(self.scrub(e) if isinstance(e, evm.EvmError)
                                                     else type(e).__name__))
        self.check_alarms(now)

    def _sync_failed(self, why, now=None):
        now = time.time() if now is None else now
        if self.sync_error_since is None:
            self.sync_error_since = now
        self.last_sync_error = why
        self.log('unusual', 'index sync failed: {}'.format(why))

    def _view(self, to, signature, types, values):
        """A uint256 view, at latest."""
        return evm.abi_decode(['uint256'], self.rpc.eth_call(to, evm.calldata(signature, types, values)))[0]

    def refresh_funds(self, force=False, now=None):
        """Reads the node key's ETH balance, its withdrawable and (token
        mode) its token balance: at most every FUNDS_MAX_AGE s, unless a send
        or new logs may have changed them, or the ETH balance is unknown or
        below evm-min-balance."""
        now = time.time() if now is None else now
        low = self.balance is None or self.balance < self.cfg.min_balance_wei
        if not (force or self.funds_dirty or low or now - self.funds_at >= FUNDS_MAX_AGE):
            return
        self.funds_dirty = False     # before the reads: a change during them marks it again
        try:
            self.balance = int(self.rpc.request('eth_getBalance', self.address, 'latest'), 16)
            self.withdrawable = self._view(self.contract, 'withdrawable(address)', ['address'], [self.address])
            if self.token is not None:
                self.token_balance = self._view(self.token, 'balanceOf(address)', ['address'], [self.address])
        except BaseException:
            self.funds_dirty = True
            raise
        self.funds_at = now

    def margin(self):
        """The smallest margin of SPEC 5.6, in blocks: the to_self_delay we
        demand, and half the HTLC deltas (CLN goes on chain (delta+1)/2
        blocks before expiry). From lightningd's values once checked, else
        the minimums."""
        mins = option_minimums(self.interval, self.chain_id())[0]
        vals = {}
        for k in ('watchtime-blocks', 'cltv-delta', 'cltv-final'):
            v = _config_value(self.cln_configs, k)
            vals[k] = v if _is_int(v) and v > 0 else mins[k]
        return min(vals['watchtime-blocks'], (vals['cltv-delta'] + 1) // 2, (vals['cltv-final'] + 1) // 2)

    def lag(self):
        """L of SPEC 3.4: H(latest) - tip, plus CLN's poll time, in blocks.
        Until the option check has read lightningd's poll, the poll 5.6
        demands is assumed (else every start would alarm)."""
        h = self.ix.current_height()
        if h is None:
            return None
        # Heights follow the wall clock (3.1): during an outage the last
        # sync's H(latest) freezes, but the timelocks still run down.
        h = max(h, self.ix.height_at(int(time.time())))
        poll = self.cln_poll if self.options_checked else max(1, self.interval // 2)
        return h - self.ix.tip() + poll / float(self.interval)

    def check_alarms(self, now=None):
        """SPEC 5.5's alarms, at BROKEN level when raised (and every 10
        minutes while they last), info when cleared."""
        now = time.time() if now is None else now
        tb = self.ix.tag_block()
        if tb is not None and (self.tag_seen is None or self.tag_seen[0] != tb[0]):
            self.tag_seen = (tb[0], now)
        lag = self.lag()
        margin = self.margin()
        found = {}
        if lag is not None and lag > margin / 3.0:
            found['lag'] = 'lag L = {:.1f} blocks is above a third of the smallest margin ({} blocks)'.format(
                lag, margin)
        if self.tag_seen is not None and now - self.tag_seen[1] > 10 * self.interval:
            found['tag'] = 'the {} block has not advanced for {:.0f} s (10 x INTERVAL is {} s)'.format(
                self.cfg.confirm, now - self.tag_seen[1], 10 * self.interval)
        if self.balance is not None and self.balance < self.cfg.min_balance_wei:
            found['balance'] = 'ETH balance of {} is {} wei, below evm-min-balance ({} wei): new channels refused' \
                .format(self.address, self.balance, self.cfg.min_balance_wei)
        if self.sync_error_since is not None and now - self.sync_error_since > 5 * self.interval:
            found['sync'] = 'index sync failing for {:.0f} s (last: {})'.format(
                now - self.sync_error_since, self.last_sync_error)
        for name, msg in found.items():
            a = self.alarms.get(name)
            if a is None or now - a['logged'] >= 600:
                self.log('broken', 'alarm: ' + msg)
                self.alarms[name] = {'since': a['since'] if a else now, 'logged': now, 'message': msg}
            else:
                a['message'] = msg
        for name in [n for n in self.alarms if n not in found]:
            del self.alarms[name]
            self.log('info', 'alarm cleared: {}'.format(name))
        return found

    # -------------------------------------------------------- the option check (5.6)

    def _option_check_loop(self):
        while not self.stop_event.is_set():
            try:
                rpc = self.lnrpc()
                configs = rpc.call('listconfigs')['configs']
                info = rpc.call('getinfo')
            except Exception:
                self.stop_event.wait(1)
                continue
            self.apply_option_check(configs, info)
            return

    def apply_option_check(self, configs, info):
        self.cln_configs = configs
        self.cln_poll = cln_poll_seconds(configs)
        self.option_problems = check_options(configs, info, self.interval, self.chain_id(), self.contract)
        self.options_checked = True
        for p in self.option_problems:
            self.log('broken', 'CLN option below SPEC 5.6: {}; channel opens are refused until restarted '
                     'with correct values'.format(p))
        if not self.option_problems:
            self.log('info', 'CLN options meet SPEC 5.6')

    def open_refusal(self):
        """Why new channels are refused now (5.1, 5.6), or None."""
        if not self.options_checked:
            return 'evmbackend has not checked lightningd\'s options yet'
        if self.option_problems:
            return 'lightningd runs with options below SPEC 5.6: ' + '; '.join(self.option_problems)
        if self.balance is None:
            return 'the node\'s ETH balance is unknown'
        if self.balance < self.cfg.min_balance_wei:
            return 'the node\'s ETH balance is below evm-min-balance'
        return None

    # -------------------------------------------------------- hooks (5.4)

    def peer_connected(self, peer):
        try:
            anchors = any(feature_set(peer.get('features') or '', b) for b in ANCHOR_BITS)
        except (AttributeError, TypeError, ValueError):
            anchors = False
        if anchors:
            return {'result': 'continue'}
        self.log('info', 'disconnecting peer {}: no anchors_zero_fee_htlc_tx (feature 22/23)'.format(
            peer.get('id') if isinstance(peer, dict) else '?'))
        return {'result': 'disconnect',
                'error_message': 'this node only opens anchors_zero_fee_htlc_tx channels (feature 22/23)'}

    def _open_problem(self, payload):
        why = self.open_refusal()
        if why:
            return 'channel opens are refused: ' + why
        ct = payload.get('channel_type')
        if not isinstance(ct, dict):
            return 'no channel_type: only anchors_zero_fee_htlc_tx channels are supported'
        why = ctype_problem(ct.get('bits'))
        if why:
            return why
        try:
            mah = int(payload.get('max_accepted_htlcs'))
        except (TypeError, ValueError):
            return 'cannot read max_accepted_htlcs'
        if mah > MAX_HTLCS:
            return 'max_accepted_htlcs {} is above {} (the EVM gas cap)'.format(mah, MAX_HTLCS)
        return None

    def openchannel(self, oc):
        why = self._open_problem(oc)
        if why:
            self.log('info', 'refused an open from {}: {}'.format(oc.get('id'), why))
            return {'result': 'reject', 'error_message': why}
        return {'result': 'continue'}

    def openchannel2(self, oc2):
        """Dual funding would need every funding input checked (the contract
        spends only P2WPKH and P2TR): this build refuses it instead."""
        why = 'dual-funded opens are not supported on EVM channels'
        self.log('info', 'refused a dual-funded open from {}: {}'.format(oc2.get('id'), why))
        return {'result': 'reject', 'error_message': why}

    # -------------------------------------------------------- RPCs (5.5)

    def _call(self, kind, to, data, value=0):
        """A call of ours from the node key: (EVM tx hash, receipt or None
        while it isn't mined). Raises UserError if it reverted on chain. The
        caller holds _send_lock."""
        txhash, receipt = self._send(to, data, value)
        if receipt is not None and int(receipt['status'], 16) != 1:
            raise UserError('{} reverted on chain (EVM tx {})'.format(kind, txhash))
        return txhash, receipt

    def _approve(self, units):
        """Token mode: lets the contract take `units` from the node key,
        unless it may already. A non-zero allowance is set to 0 first, which
        tokens like USDT require. The caller holds _send_lock."""
        have = self._view(self.token, 'balanceOf(address)', ['address'], [self.address])
        if have < units:
            raise UserError('the node key holds {} token units, below {}'.format(have, units))
        allowed = self._view(self.token, 'allowance(address,address)', ['address', 'address'],
                             [self.address, self.contract])
        if allowed >= units:
            return
        for v in ([0] if allowed else []) + [units]:
            data = evm.calldata('approve(address,uint256)', ['address', 'uint256'], [self.contract, v])
            txhash, receipt = self._call('approve', self.token, data)
            if receipt is None:
                raise UserError('approve still pending (EVM tx {}): try again once it is mined'.format(txhash))

    def deposit(self, amount, address=None):
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            raise UserError('amount must be a whole number of sats') from None
        if amount <= 0:
            raise UserError('amount must be at least 1 sat')
        if address is None:
            address = self.lnrpc().call('newaddr', {'addresstype': 'p2tr'})['p2tr']
        try:
            spk = btc.address_script(address, 'bcrt')
        except ValueError:
            raise UserError('not a bcrt segwit address') from None
        # The contract takes a deposit to any script but can only spend
        # these: one to any other (another witness version, an odd program
        # length, a P2WSH outside the channel templates) is locked for good.
        if not ((len(spk) == 22 and spk[:2] == b'\x00\x14') or (len(spk) == 34 and spk[:2] == b'\x51\x20')):
            raise UserError('deposits must go to a P2WPKH or P2TR address')
        out = {'address': address, 'amount_sat': amount}
        with self._send_lock:
            if self.token is None:
                data = evm.calldata('deposit(bytes)', ['bytes'], [spk])
                txhash, receipt = self._call('deposit', self.contract, data, amount * SAT_WEI)
            else:
                units = amount * self.units_per_sat
                self._approve(units)
                data = evm.calldata('deposit(uint256,bytes)', ['uint256', 'bytes'], [units, spk])
                txhash, receipt = self._call('deposit', self.contract, data)
                out.update({'amount_units': units, 'token': self.token})
        out['evm_tx'] = txhash
        if receipt is None:
            out['status'] = 'pending'
            return out
        for log in receipt.get('logs') or []:
            ev = self.ix.parse_log(log)
            if ev is not None:
                out['txid'] = btc.display(ev['txid'])
                out['height'] = ev['height']
        out['status'] = 'mined'
        return out

    def withdraw(self):
        with self._send_lock:
            self.refresh_funds(force=True)
            amount = self.withdrawable
            if amount == 0:
                raise UserError('nothing to withdraw for {}'.format(self.address))
            txhash, receipt = self._call('withdraw', self.contract, evm.selector('withdraw()'))
        out = {'address': self.address, 'evm_tx': txhash, 'status': 'mined' if receipt is not None else 'pending'}
        if self.token is None:
            out['amount_wei'] = amount
        else:
            out.update({'amount_units': amount, 'token': self.token})
        return out

    def exitaddr(self, ethaddress):
        try:
            return {'address': btc.exit_address(evm.address_bytes(ethaddress), 'bcrt'),
                    'ethaddress': evm.checksum_address(ethaddress)}
        except ValueError:
            raise UserError('not a 20-byte hex ETH address') from None

    def status(self, cached=False):
        """evm-status. Unless cached, the key's balances are read afresh
        first (three calls to the EVM node in token mode, two otherwise);
        cached, they are the poll's (see refresh_funds), for pollers."""
        out = {'contract': self.contract, 'chain_id': self.ix.chain_id, 'interval': self.interval,
               'confirm': self.cfg.confirm, 'eth_address': self.address, 'cached': bool(cached)}
        if not cached:
            try:
                self.refresh_funds(force=True)
            except evm.EvmError as e:
                out['balance_error'] = self.scrub(e)
        out['balance_wei'] = self.balance
        out['withdrawable_' + ('wei' if self.token is None else 'units')] = self.withdrawable
        if self.token is not None:
            out.update({'token': self.token, 'units_per_sat': self.units_per_sat,
                        'token_balance_units': self.token_balance})
        out['balance_age_s'] = round(max(0.0, time.time() - self.funds_at), 1)
        tb = self.ix.tag_block()
        out.update({'tip': self.ix.tip(), 'ibd': self.ix.ibd, 'current_height': self.ix.current_height(),
                    'lag': self.lag(), 'smallest_margin': self.margin()})
        if tb is not None:
            out.update({'tag_block': tb[0], 'tag_timestamp': tb[1], 'tag_age_s': round(time.time() - tb[1], 1)})
        if self.tag_seen is not None:
            out['tag_unchanged_s'] = round(time.time() - self.tag_seen[1], 1)
        out['alarms'] = {k: v['message'] for k, v in self.alarms.items()}
        if self.sync_error_since is not None:
            out['sync_error'] = self.last_sync_error
        if hasattr(self.rpc, 'calls'):
            with self.rpc._calls_lock:
                out['rpc_calls'] = dict(sorted(self.rpc.calls.items()))
        out['rpc_calls_since'] = self.started_at
        out['options_checked'] = self.options_checked
        out['option_problems'] = list(self.option_problems)
        out['opens_refused'] = self.open_refusal()
        return out


# ------------------------------------------------------------ pyln glue

def main():
    from pyln.client import LightningRpc, Plugin

    plugin = Plugin(dynamic=False)
    st = {}

    plugin.add_option('evm-rpc', None, 'EVM JSON-RPC URL; ${INFURA_API_KEY} is read from the environment')
    plugin.add_option('evm-contract', None, 'address of the UtxoChain contract')
    plugin.add_option('evm-key-file', None, 'file with this node\'s ETH key (default <lightning-dir>/evm-key, '
                      'created 0600)')
    plugin.add_option('evm-confirm', 'safe', 'confirmation tag: safe or latest')
    plugin.add_option('evm-poll', '60', 'seconds between index polls (1 on anvil)')
    plugin.add_option('evm-min-balance', '0.01', 'ETH below which new channels are refused')

    def log(level, msg):
        plugin.log(msg, level=level)

    def backend():
        return st['b']

    @plugin.init()
    def init(options, configuration, plugin, **kwargs):
        ldir = configuration['lightning-dir']
        rpc_path = os.path.join(ldir, configuration['rpc-file'])
        secrets = []
        try:
            cfg = Config.from_options(plugin.get_option, ldir, os.environ, log)
            secrets = cfg.secrets
            b = Backend(cfg, log, lnrpc=lambda: LightningRpc(rpc_path))
            b.connect()
        except Exception as e:     # noqa: B902 - lightningd can't run without its backend: like bcli, exit
            why = scrub_text(e, secrets) if isinstance(e, (ConfigError, evm.EvmError, evmindex.EvmIndexError)) \
                else type(e).__name__
            plugin.log('evmbackend cannot start: {}'.format(why), level='broken')
            sys.stdout.flush()
            time.sleep(0.5)
            os._exit(1)
        b.start()
        st['b'] = b

    def guard(name, fn, fallback):
        try:
            return fn()
        except Exception as e:
            log('broken', '{}: internal error ({})'.format(name, type(e).__name__))
            return fallback() if callable(fallback) else fallback

    def in_thread(name, fn, request):
        """Answers one of our RPCs with fn() from a new thread; errors go
        back to the caller as JSON-RPC errors."""
        def run():
            msg, result = None, None
            try:
                result = fn()
            except (UserError, evm.EvmError) as e:     # written by us / method, type and code only
                msg = backend().scrub(e)
            except Exception as e:                     # noqa: B902
                msg = 'internal error ({})'.format(type(e).__name__)
                log('broken', '{}: {}'.format(name, msg))
            # Outside the except blocks: pyln's set_exception attaches
            # traceback.format_exc(), which is then empty instead of holding
            # str(e) and source lines.
            if msg is None:
                request.set_result(result)
            else:
                from pyln.client.plugin import RpcException
                request.set_exception(RpcException(msg))
        threading.Thread(target=run, name=name, daemon=True).start()

    # --- the five backend methods: never a JSON-RPC error

    @plugin.method('getchaininfo')
    def getchaininfo(plugin, last_height=None, **kwargs):
        return guard('getchaininfo', lambda: backend().getchaininfo(), lambda: backend().getchaininfo_fallback())

    @plugin.method('getrawblockbyheight')
    def getrawblockbyheight(plugin, height, **kwargs):
        return guard('getrawblockbyheight', lambda: backend().getrawblockbyheight(height),
                     {'blockhash': None, 'block': None})

    @plugin.method('getutxout')
    def getutxout(plugin, txid, vout, **kwargs):
        return guard('getutxout', lambda: backend().getutxout(txid, vout), {'amount': None, 'script': None})

    @plugin.method('estimatefees')
    def estimatefees(plugin, **kwargs):
        return Backend.estimatefees(None)

    @plugin.async_method('sendrawtransaction')
    def sendrawtransaction(plugin, request, tx, allowhighfees=False, **kwargs):
        def run():
            request.set_result(guard('sendrawtransaction', lambda: backend().sendrawtransaction(tx),
                                     fail('internal error')))
        threading.Thread(target=run, name='sendrawtransaction', daemon=True).start()

    # --- hooks (5.4)

    @plugin.hook('peer_connected')
    def on_peer_connected(peer, plugin, **kwargs):
        return guard('peer_connected', lambda: backend().peer_connected(peer),
                     {'result': 'disconnect', 'error_message': 'internal error'})

    # Before funder: a bare 'continue' from a later plugin would wipe the
    # PSBT and amount funder contributed (dual_open_control.c).
    def on_openchannel(openchannel, plugin, **kwargs):
        return guard('openchannel', lambda: backend().openchannel(openchannel),
                     {'result': 'reject', 'error_message': 'internal error'})
    plugin.add_hook('openchannel', on_openchannel, before=['funder'])

    def on_openchannel2(openchannel2, plugin, **kwargs):
        return guard('openchannel2', lambda: backend().openchannel2(openchannel2),
                     {'result': 'reject', 'error_message': 'internal error'})
    plugin.add_hook('openchannel2', on_openchannel2, before=['funder'])

    # --- RPCs (5.5)

    @plugin.async_method('evm-deposit')
    def evm_deposit(plugin, request, amount, address=None, **kwargs):
        """Deposits {amount} sats from the node's ETH key (ETH, or the token: approved first) to {address}
        (default: a new p2tr address)."""
        in_thread('evm-deposit', lambda: backend().deposit(amount, address), request)

    @plugin.method('evm-exitaddr')
    def evm_exitaddr(plugin, ethaddress, **kwargs):
        """The bcrt1s... address that `withdraw` pays out to {ethaddress}."""
        try:
            return backend().exitaddr(ethaddress)
        except UserError as e:
            from pyln.client.plugin import RpcException
            raise RpcException(str(e)) from None

    @plugin.async_method('evm-withdraw')
    def evm_withdraw(plugin, request, **kwargs):
        """Withdraws the node key's withdrawable ETH or token (fees and exits) from the contract."""
        in_thread('evm-withdraw', lambda: backend().withdraw(), request)

    @plugin.async_method('evm-status')
    def evm_status(plugin, request, cached=False, **kwargs):
        """Contract, chain, key, balances (ETH, and the token in token mode), tip, lag, alarms;
        {cached}=true reads no fresh balances (the poll's)."""
        flag = cached is True or (isinstance(cached, str) and cached.lower() in ('true', '1'))
        in_thread('evm-status', lambda: backend().status(cached=flag), request)

    plugin.run()


if __name__ == '__main__':
    main()
