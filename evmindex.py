# SPDX-License-Identifier: MIT
"""The index (minimal build): every TxApplied log of the UtxoChain contract,
kept in SQLite, and the virtual chain of SPEC 3 served from it.

    ix = Index(path, evm.EvmRpc(url), contract, tag='safe', log=None)
    ix.sync()                     # one poll
    ix.add_receipt(receipt)       # our own submit, before the next poll
    ix.tip(), ix.ibd              # SPEC 3.4
    ix.block(h)                   # (hash hex, raw block) for h <= tip, else None
    ix.utxo(txid_hex, vout)       # {'amount', 'script', 'height'} or None

What it trusts. The EVM node's answers are taken as they come: there are no
checkpoints against the contract's logHash, no repair, no snapshots (SPEC 5.2
has all three; this build is for testnets). One rule keeps it right against a
node that merely lags, or an EVM reorg above the confirmation tag:

- Rows in EVM blocks at or below the tag block (`safe` by default) are final:
  read once, never changed. `cursor` is the highest such block read.
- Rows above it are provisional: every poll deletes and re-reads them, up to
  `latest`. They are never in a served block (the tip is below the tag, SPEC
  3.4), but the UTXO set counts them, so a tx can spend the outputs of one
  that was just mined.

So a reorg below the tag is NOT handled: with tag `latest` (anvil) that is any
reorg. Delete the file to rebuild it from the chain.

Txids. Public methods take and return display-order hex; the database and
btc.py's bytes are internal order.

Threading. One SQLite connection, guarded by one lock; no network call is
made while holding it. `sync()` runs one at a time; `add_receipt` and the
readers may run concurrently with it.

Logging. `log(level, message)` with level 'broken', 'unusual', 'info' or
'debug'. Messages hold block numbers and txids, never the RPC URL or a
reply's text.
"""
import logging
import sqlite3
import threading

import btc
import evm

TX_APPLIED = 'TxApplied(uint32,bytes32,bytes)'
TOPIC0 = '0x' + evm.keccak256(TX_APPLIED.encode()).hex()
TAGS = ('safe', 'latest')   # SPEC 3.4: `finalized` is not supported
SCHEMA_VERSION = 3
HEADER_BATCH = 5000         # header hashes computed per lock hold
ZERO32 = bytes(32)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value);
-- One row per TxApplied log. txid is internal byte order.
CREATE TABLE IF NOT EXISTS txs (
    id INTEGER PRIMARY KEY,
    evm_block INTEGER NOT NULL,
    log_index INTEGER NOT NULL,
    height INTEGER NOT NULL,
    txid BLOB NOT NULL,
    raw BLOB NOT NULL,
    UNIQUE (evm_block, log_index));
CREATE INDEX IF NOT EXISTS txs_height ON txs (height, evm_block, log_index);
CREATE INDEX IF NOT EXISTS txs_txid ON txs (txid);
CREATE TABLE IF NOT EXISTS outputs (
    tx_id INTEGER NOT NULL,
    vout INTEGER NOT NULL,
    txid BLOB NOT NULL,
    amount INTEGER NOT NULL,
    script BLOB NOT NULL,
    height INTEGER NOT NULL,
    spendable INTEGER NOT NULL,
    PRIMARY KEY (tx_id, vout));
CREATE INDEX IF NOT EXISTS outputs_outpoint ON outputs (txid, vout);
CREATE TABLE IF NOT EXISTS spends (
    tx_id INTEGER NOT NULL,
    vin INTEGER NOT NULL,
    prev_txid BLOB NOT NULL,
    prev_vout INTEGER NOT NULL,
    PRIMARY KEY (tx_id, vin));
CREATE INDEX IF NOT EXISTS spends_prev ON spends (prev_txid, prev_vout);
-- Block hashes of heights 0..m (always a prefix), derived from final rows
-- only, so they never change.
CREATE TABLE IF NOT EXISTS headers (height INTEGER PRIMARY KEY, hash BLOB NOT NULL);
"""


class EvmIndexError(Exception):
    """The index cannot be used as asked (wrong file, bad tag, no contract)."""


def _int(x):
    return int(x, 16) if isinstance(x, str) else int(x)


def _default_log(level, message):
    logging.getLogger('evmindex').log(
        {'broken': logging.ERROR, 'unusual': logging.WARNING, 'info': logging.INFO}.get(level, logging.DEBUG),
        message)


class Index:
    def __init__(self, path, rpc, contract, tag='safe', log=None):
        """Opens (or creates) the index at `path` for `contract` on `rpc`'s
        chain. Reads the chain id and the contract's DEPLOY_BLOCK, GENESIS_TIME
        and INTERVAL (SPEC 5.1) and checks them against the file's, so a file
        is never reused for another contract or chain. Raises evm.EvmError if
        the node can't be reached, EvmIndexError on any mismatch."""
        if tag not in TAGS:
            raise EvmIndexError('confirmation tag must be one of {}, not {!r}'.format(TAGS, tag))
        self.rpc, self.tag, self.log = rpc, tag, log or _default_log
        self.contract = evm.checksum_address(contract)
        self._lock = threading.RLock()
        self._sync_lock = threading.Lock()
        self.ibd = True             # until a sync of this process has reached the tag
        self._latest = None         # (number, timestamp) of `latest` at the last sync
        self._tagblock = None       # the same for the tag

        if not rpc.code(self.contract):
            raise EvmIndexError('no contract code at {}'.format(self.contract))
        self.chain_id = rpc.chain_id()
        self.deploy_block = self._read_const('DEPLOY_BLOCK')
        self.genesis_time = self._read_const('GENESIS_TIME')
        self.interval = self._read_const('INTERVAL')
        if self.interval == 0:
            raise EvmIndexError('INTERVAL is 0')

        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        with self._lock:
            self._db.execute('PRAGMA journal_mode=WAL')
            self._db.execute('PRAGMA synchronous=FULL')    # the tip must survive a power loss
            want = {'schema': SCHEMA_VERSION, 'contract': self.contract.lower(), 'chain_id': self.chain_id,
                    'deploy_block': self.deploy_block, 'genesis_time': self.genesis_time,
                    'interval': self.interval}
            with self._tx():
                self._db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value)')
                have = dict(self._db.execute('SELECT key, value FROM meta'))
                for k, v in want.items():
                    if k in have and have[k] != v:
                        raise EvmIndexError('{} is for {} {}, not {}: delete it, it is rebuilt from the chain'
                                            .format(path, k, have[k], v))
                for stmt in _SCHEMA.split(';'):
                    if stmt.strip():
                        self._db.execute(stmt)
                for k, v in want.items():
                    self._set_meta(k, v)

    def _read_const(self, name):
        return evm.abi_decode(['uint256'], self.rpc.eth_call(self.contract, evm.selector(name + '()')))[0]

    def close(self):
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------ db helpers

    class _Txn:
        def __init__(self, db):
            self.db = db

        def __enter__(self):
            self.db.execute('BEGIN IMMEDIATE')

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.db.execute('COMMIT')
            elif self.db.in_transaction:     # SQLite may already have rolled back (e.g. disk full)
                try:
                    self.db.execute('ROLLBACK')
                except sqlite3.Error:
                    pass                     # keep the original exception
            return False

    def _tx(self):
        """A write transaction; the caller holds self._lock."""
        return self._Txn(self._db)

    def _meta(self, key, default=None):
        row = self._db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
        return default if row is None else row[0]

    def _set_meta(self, key, value):
        self._db.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', (key, value))

    def _cursor(self):
        """Rows in EVM blocks up to this number are final."""
        return self._meta('cursor', self.deploy_block - 1)

    # ------------------------------------------------------------ rows

    def parse_log(self, log):
        """A TxApplied log (from eth_getLogs or a receipt) -> {'block',
        'log_index', 'height', 'txid', 'raw', 'tx'}, or None if it isn't this
        contract's TxApplied, or its raw tx doesn't decode to its txid (logged
        at BROKEN level: the contract only applies txs it parsed). Never
        raises."""
        try:
            if evm.unhex(log['address']) != evm.address_bytes(self.contract) or log.get('removed'):
                return None
            topics = [evm.unhex(t) for t in log['topics']]
            if len(topics) != 3 or '0x' + topics[0].hex() != TOPIC0 or any(len(t) != 32 for t in topics):
                return None
            block, li = _int(log['blockNumber']), _int(log['logIndex'])
            height, txid = int.from_bytes(topics[1], 'big'), topics[2]
        except Exception:
            return None         # pending, or not a log at all
        try:
            raw = evm.abi_decode(['bytes'], evm.unhex(log['data']))[0]
            tx = btc.Tx.parse(raw)
            if tx.txid() != txid or height < 1:
                raise ValueError
        except Exception:
            self.log('broken', 'undecodable TxApplied {} in EVM block {} log {}: skipped'.format(
                btc.display(txid), block, li))
            return None
        return {'block': block, 'log_index': li, 'height': height, 'txid': txid, 'raw': raw, 'tx': tx}

    def _insert(self, ev):
        """Stores one event unless its block and log index are taken; the
        caller holds the lock and a transaction."""
        db = self._db
        cur = db.execute('INSERT OR IGNORE INTO txs (evm_block, log_index, height, txid, raw) VALUES (?, ?, ?, ?, ?)',
                         (ev['block'], ev['log_index'], ev['height'], ev['txid'], ev['raw']))
        if cur.rowcount != 1:
            return
        row_id, tx = cur.lastrowid, ev['tx']
        # SPEC 4.4: an exit or an OP_RETURN output is never a UTXO.
        db.executemany('INSERT INTO outputs (tx_id, vout, txid, amount, script, height, spendable) '
                       'VALUES (?, ?, ?, ?, ?, ?, ?)',
                       [(row_id, i, ev['txid'], amount, spk, ev['height'],
                         0 if btc.is_exit_script(spk) or btc.is_op_return(spk) else 1)
                        for i, (amount, spk) in enumerate(tx.outputs)])
        db.executemany('INSERT INTO spends (tx_id, vin, prev_txid, prev_vout) VALUES (?, ?, ?, ?)',
                       [(row_id, i, txin.prev_txid, txin.vout) for i, txin in enumerate(tx.inputs)])

    def _delete_blocks(self, lo, hi):
        """Removes the rows of EVM blocks lo..hi; the caller holds the lock
        and a transaction."""
        ids = '(SELECT id FROM txs WHERE evm_block BETWEEN ? AND ?)'
        self._db.execute('DELETE FROM outputs WHERE tx_id IN ' + ids, (lo, hi))
        self._db.execute('DELETE FROM spends WHERE tx_id IN ' + ids, (lo, hi))
        self._db.execute('DELETE FROM txs WHERE evm_block BETWEEN ? AND ?', (lo, hi))

    def add_receipt(self, receipt):
        """Ingests the TxApplied logs of a mined receipt at once (our own
        sends), so their outputs can be spent before the next poll. Returns
        their txids (display hex)."""
        if not isinstance(receipt, dict) or _int(receipt.get('status', '0x0')) != 1:
            return []
        events = [ev for ev in (self.parse_log(x) for x in receipt.get('logs') or []) if ev is not None]
        with self._lock, self._tx():
            for ev in events:
                self._insert(ev)
        return [btc.display(ev['txid']) for ev in events]

    # ------------------------------------------------------------ polling

    def sync(self):
        """One poll: re-reads the logs above the cursor up to `latest`, moves
        the cursor to the tag block and the tip to its candidate (SPEC 3.4).
        Returns True if any row changed, False if none did, None if the poll
        was skipped (a node behind the previous poll's). Raises evm.EvmError
        on RPC failure; the ranges already read stay."""
        with self._sync_lock:
            tagb = self.rpc.block(self.tag)
            latest = tagb if self.tag == 'latest' else self.rpc.block('latest')
            try:
                tag_n, tag_ts = _int(tagb['number']), _int(tagb['timestamp'])
                lat_n, lat_ts = _int(latest['number']), _int(latest['timestamp'])
            except Exception:
                raise evm.EvmError('eth_getBlockByNumber: bad reply') from None
            with self._lock:
                cursor = self._cursor()
            if tag_n < cursor or lat_n < tag_n:
                self.log('unusual', 'stale EVM node: {} block {}, latest {}, after block {}; poll skipped'.format(
                    self.tag, tag_n, lat_n, cursor))
                return None
            self._tagblock, self._latest = (tag_n, tag_ts), (lat_n, lat_ts)
            changed = False
            for first, last, logs in self.rpc.get_logs_chunked(self.contract, [TOPIC0], cursor + 1, lat_n):
                events = [ev for ev in (self.parse_log(x) for x in logs if isinstance(x, dict)) if ev is not None]
                with self._lock, self._tx():
                    had = self._db.execute('SELECT evm_block, log_index, txid FROM txs WHERE evm_block '
                                           'BETWEEN ? AND ? ORDER BY evm_block, log_index', (first, last)).fetchall()
                    if had != [(ev['block'], ev['log_index'], ev['txid']) for ev in events]:
                        changed = True
                        self._delete_blocks(first, last)
                        for ev in events:
                            self._insert(ev)
                    self._set_meta('cursor', max(cursor, min(last, tag_n)))
            with self._lock, self._tx():
                self._set_meta('cursor', max(cursor, tag_n))
                self._set_meta('tip', max(self._meta('tip', 0), self.height_at(tag_ts) - 1))
            self.ibd = False
            return changed

    # ------------------------------------------------------------ the virtual chain

    def height_at(self, timestamp):
        """H(t), which is negative before GENESIS_TIME."""
        return (timestamp - self.genesis_time) // self.interval

    def tip(self):
        """The reported tip: the highest candidate seen, persisted, never lower."""
        with self._lock:
            return self._meta('tip', 0)

    def current_height(self):
        """H(latest) as of the last sync, or None before one."""
        return None if self._latest is None else max(self.height_at(self._latest[1]), 0)

    def tag_block(self):
        """(number, timestamp) of the tag block at the last sync, or None."""
        return self._tagblock

    def _cached_top(self):
        row = self._db.execute('SELECT MAX(height) FROM headers').fetchone()
        return -1 if row[0] is None else row[0]

    def _final_rows(self, lo, hi):
        return self._db.execute('SELECT height, txid, raw FROM txs WHERE height BETWEEN ? AND ? '
                                'AND evm_block <= ? ORDER BY height, evm_block, log_index',
                                (lo, hi, self._cursor()))

    def _fill_headers(self, upto):
        """Computes the header hashes of heights (cached top + 1)..upto, at most
        HEADER_BATCH of them; the caller holds the lock."""
        top = self._cached_top()
        first, last = top + 1, min(upto, top + HEADER_BATCH)
        if first > last:
            return
        prev = ZERO32 if first == 0 else self._db.execute(
            'SELECT hash FROM headers WHERE height = ?', (top,)).fetchone()[0]
        txids = {}
        for h, txid, _ in self._final_rows(first, last):
            txids.setdefault(h, []).append(txid)
        rows = []
        for h in range(first, last + 1):
            hdr, _ = btc.block_header(h, prev, txids.get(h, []), self.genesis_time, self.interval)
            prev = btc.block_hash(hdr)
            rows.append((h, prev))
        with self._tx():
            self._db.executemany('INSERT INTO headers (height, hash) VALUES (?, ?)', rows)

    def block(self, h):
        """Virtual block h of SPEC 3.2: (block hash, display hex; raw block
        bytes), or None above the tip."""
        if h < 0:
            return None
        while True:
            with self._lock:
                if h > self._meta('tip', 0):
                    return None
                if h > 0 and self._cached_top() < h - 1:
                    self._fill_headers(h - 1)
                    continue    # let other threads in between batches
                prev = ZERO32 if h == 0 else self._db.execute(
                    'SELECT hash FROM headers WHERE height = ?', (h - 1,)).fetchone()[0]
                rows = self._final_rows(h, h).fetchall()
                raw, hsh = btc.build_block(h, prev, [r[2] for r in rows], self.genesis_time,
                                           self.interval, txids=[r[1] for r in rows])
                if self._cached_top() == h - 1:
                    with self._tx():
                        self._db.execute('INSERT INTO headers (height, hash) VALUES (?, ?)', (h, hsh))
                return btc.display(hsh), raw

    # ------------------------------------------------------------ outputs

    def utxo_internal(self, txid, vout):
        """{'amount': sats, 'script': bytes, 'height': h} of an unspent output
        as of `latest` (everything indexed), or None if it is unknown, spent,
        an exit or an OP_RETURN. txid in internal byte order."""
        with self._lock:
            row = self._db.execute('SELECT amount, script, height, spendable FROM outputs WHERE txid = ? AND vout = ?',
                                   (bytes(txid), vout)).fetchone()
            if row is None or not row[3]:
                return None
            if self._db.execute('SELECT 1 FROM spends WHERE prev_txid = ? AND prev_vout = ? LIMIT 1',
                                (bytes(txid), vout)).fetchone():
                return None
            return {'amount': row[0], 'script': row[1], 'height': row[2]}

    def utxo(self, txid_hex, vout):
        """utxo_internal for a display-order hex txid (getutxout's)."""
        return self.utxo_internal(btc.internal(txid_hex), vout)

    def tx(self, txid_hex):
        """{'height', 'evm_block', 'log_index', 'raw'} of an indexed tx
        (display-order hex txid), or None."""
        with self._lock:
            row = self._db.execute('SELECT height, evm_block, log_index, raw FROM txs WHERE txid = ?',
                                   (btc.internal(txid_hex),)).fetchone()
        if row is None:
            return None
        return {'height': row[0], 'evm_block': row[1], 'log_index': row[2], 'raw': row[3]}

    def prevouts(self, tx):
        """[(amount, script, height)] for each input of a btc.Tx, as `submit`
        takes them, or None if any input is unknown or spent."""
        out = []
        for txin in tx.inputs:
            u = self.utxo_internal(txin.prev_txid, txin.vout)
            if u is None:
                return None
            out.append((u['amount'], u['script'], u['height']))
        return out
