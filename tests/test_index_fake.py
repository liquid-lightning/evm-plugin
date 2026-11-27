# SPDX-License-Identifier: MIT
"""evmindex (minimal build) against an in-memory node (fakechain.py): the
tip, final and provisional rows, a reorg above the tag, the result and range
splits of eth_getLogs, a bad event, persistence and concurrent readers.
test_index_anvil.py does the same against the contract."""
import threading

import pytest

import btc
import evm
import evmindex
from fakechain import CONTRACT, FakeChain
from test_btc import ref_block


def all_blocks(ix):
    return [ix.block(h) for h in range(ix.tip() + 1)]


def check_chain(ix, node):
    """Every block <= tip, rebuilt independently from the node's logs."""
    by_height = {}
    for b in node.blocks:
        for log in b['logs']:
            h = int(log['topics'][1], 16)
            raw = evm.abi_decode(['bytes'], evm.unhex(log['data']))[0]
            by_height.setdefault(h, []).append(raw)
    prev = bytes(32)
    for h in range(ix.tip() + 1):
        raws = by_height.get(h, [])
        want, whash = ref_block(h, prev, raws, [btc.txid_of(r) for r in raws], node.G, node.I)
        got_hash, got = ix.block(h)
        assert got == want and got_hash == btc.display(whash), h
        prev = whash


def fresh(tmp_path, node, name='ix.sqlite3', tag='safe'):
    return evmindex.Index(str(tmp_path / name), node, CONTRACT, tag)


def txid(raw):
    return btc.Tx.parse(raw).txid_hex()


def test_sync_tip_and_blocks(tmp_path):
    node = FakeChain()
    ix = fresh(tmp_path, node)
    assert ix.ibd and ix.tip() == 0 and ix.current_height() is None
    assert btc.parse_block(ix.block(0)[1])[0][4:36] == bytes(32)    # block 0, before any sync
    d1, d2, d3 = node.deposit(), node.deposit(), node.deposit()
    node.add_block(node.T(1), [d1, d2])
    node.add_block(node.T(1) + 1, [d3])
    node.add_block(node.T(4))
    node.add_block(node.T(4) + 1)
    assert ix.sync() is True
    assert not ix.ibd
    # safe = the block at T(4): candidate H(T(4)) - 1 = 3.
    assert ix.tip() == 3 and ix.current_height() == 4
    check_chain(ix, node)
    _, raw = ix.block(1)
    hdr, txs = btc.parse_block(raw)
    assert [t.serialize() for t in txs[1:]] == [d1, d2, d3]
    for h in (0, 2, 3):
        assert len(btc.parse_block(ix.block(h)[1])[1]) == 1     # coinbase only
    assert ix.block(4) is None and ix.block(-1) is None
    u = ix.utxo(txid(d1), 0)
    assert u == {'amount': 1000, 'script': btc.Tx.parse(d1).outputs[0][1], 'height': 1}
    assert ix.utxo(txid(d1), 1) is None
    assert ix.tx(txid(d3))['height'] == 1
    assert ix.sync() is False       # nothing new


def test_tip_never_decreases_and_a_node_behind_is_skipped(tmp_path):
    node = FakeChain()
    ix = fresh(tmp_path, node)
    for h in range(1, 8):
        node.add_block(node.T(h))
    ix.sync()
    assert ix.tip() == 5        # safe is at T(6)
    node.hide = 3               # another backend, three blocks behind: its safe is below ours
    assert ix.sync() is None and ix.tip() == 5
    node.hide = 0
    assert ix.sync() is False and ix.tip() == 5
    check_chain(ix, node)


def test_latest_tag(tmp_path):
    node = FakeChain()
    ix = fresh(tmp_path, node, tag='latest')
    node.add_block(node.T(3))
    ix.sync()
    assert ix.tip() == 2
    with pytest.raises(evmindex.EvmIndexError):
        fresh(tmp_path, node, 'other.sqlite3', tag='finalized')


def test_rows_above_the_tag_are_provisional(tmp_path):
    """The block above `safe` is re-read every poll: its outputs can be
    spent at once, it is in no served block, and a reorg of it is followed."""
    node = FakeChain()
    ix = fresh(tmp_path, node)
    keep, gone, moved = node.deposit(), node.deposit(), node.deposit()
    node.add_block(node.T(1), [keep])
    node.add_block(node.T(2), [gone, moved])
    ix.sync()                                   # safe: the block of `keep`; `gone` and `moved` are above it
    assert all(ix.utxo(txid(d), 0) for d in (keep, gone, moved))
    assert ix.tip() == 0                        # H(T(1)) - 1: no block holds them yet
    top = node.blocks[-1]['number']
    node.reorg(top)                             # the EVM chain replaces that block
    other = node.deposit()
    node.add_block(node.T(2), [other])          # same number, another tx
    node.add_block(node.T(3), [moved])          # the same tx, one block later
    assert ix.sync() is True
    assert ix.utxo(txid(gone), 0) is None and ix.tx(txid(gone)) is None
    assert ix.utxo(txid(other), 0)['height'] == 2
    assert ix.tx(txid(moved))['evm_block'] == top + 1
    node.add_block(node.T(6))
    node.add_block(node.T(6) + 1)
    ix.sync()
    assert ix.tip() == 5
    check_chain(ix, node)


def test_add_receipt_before_sync(tmp_path):
    node = FakeChain()
    ix = fresh(tmp_path, node)
    d = node.deposit()
    b = node.add_block(node.T(1), [d])
    assert ix.utxo(txid(d), 0) is None
    assert ix.add_receipt(node.receipt(b)) == [txid(d)]
    assert ix.utxo(txid(d), 0)['height'] == 1
    assert ix.add_receipt(node.receipt(b)) == [txid(d)]   # idempotent
    assert ix.add_receipt(dict(node.receipt(b), status='0x0')) == []
    assert ix.sync() is False       # the poll reads the same row: nothing changed
    node.add_block(node.T(3))
    node.add_block(node.T(3) + 1)
    ix.sync()
    check_chain(ix, node)


def test_spent_outputs_exits_and_op_returns_are_not_utxos(tmp_path):
    node = FakeChain()
    ix = fresh(tmp_path, node)
    d = btc.Tx.parse(node.deposit())
    spend = btc.Tx(2, [btc.TxIn(d.txid(), 0)], [(400, b'\x00\x14' + bytes(20)), (300, btc.exit_script(bytes(20))),
                                                (0, b'\x6a\x01\x00')])
    node.add_block(node.T(1), [d.serialize()])
    assert ix.sync() and ix.prevouts(spend) == [(1000, d.outputs[0][1], 1)]
    node.add_block(node.T(2), [spend.serialize()])
    ix.sync()
    assert ix.utxo(d.txid_hex(), 0) is None and ix.prevouts(spend) is None
    assert ix.utxo(spend.txid_hex(), 0)['amount'] == 400
    assert ix.utxo(spend.txid_hex(), 1) is None and ix.utxo(spend.txid_hex(), 2) is None


def test_split_through_the_index(tmp_path):
    node = FakeChain(max_logs=50)
    ix = fresh(tmp_path, node)
    raws = []
    for i in range(40):
        batch = [node.deposit() for _ in range(10)]
        raws += batch
        node.add_block(node.T(1) + i, batch)
    node.add_block(node.T(25))
    node.add_block(node.T(25) + 1)
    ix.sync()
    assert all(ix.utxo(txid(r), 0) for r in raws)
    assert len(logs_ranges(node)) > 3
    check_chain(ix, node)


def test_undecodable_event_is_skipped_and_logged(tmp_path):
    """The contract only emits txs it parsed, so a raw tx that isn't its
    txid's is a bad reply: logged at BROKEN level, never served."""
    node = FakeChain()
    logged = []
    ix = evmindex.Index(str(tmp_path / 'u.sqlite3'), node, CONTRACT, log=lambda lv, m: logged.append((lv, m)))
    good, other = node.deposit(), node.deposit()
    node.add_block(node.T(1), [good, (b'\x02\x00\x00\x00junk', btc.Tx.parse(other).txid())])
    node.add_block(node.T(2))
    node.add_block(node.T(2) + 1)
    ix.sync()
    assert 'broken' in [lv for lv, _ in logged] and all('junk' not in m for _, m in logged)
    assert ix.tx(txid(good)) is not None and ix.tx(txid(other)) is None
    assert [t.serialize() for t in btc.parse_block(ix.block(1)[1])[1][1:]] == [good]


def test_persistence(tmp_path):
    node = FakeChain()
    path = str(tmp_path / 'p.sqlite3')
    ix = evmindex.Index(path, node, CONTRACT)
    d = node.deposit()
    node.add_block(node.T(1), [d])
    for h in range(2, 8):
        node.add_block(node.T(h))
    ix.sync()
    blocks, tip = all_blocks(ix), ix.tip()
    ix.close()
    n_calls = node.count('eth_getLogs')
    ix = evmindex.Index(path, node, CONTRACT)
    assert ix.ibd and ix.tip() == tip and all_blocks(ix) == blocks
    assert ix.utxo(txid(d), 0)['height'] == 1
    assert node.count('eth_getLogs') == n_calls
    ix.sync()
    assert not ix.ibd and all_blocks(ix)[:len(blocks)] == blocks
    ix.close()
    other = FakeChain(interval=3)
    with pytest.raises(evmindex.EvmIndexError) as e:
        evmindex.Index(path, other, CONTRACT)
    assert 'delete it' in str(e.value)
    with pytest.raises(evmindex.EvmIndexError):
        evmindex.Index(path, node, '0x' + '11' * 20)       # no code there


def test_readers_during_sync(tmp_path):
    node = FakeChain(max_logs=30)
    ix = fresh(tmp_path, node)
    raws = []
    for h in range(1, 300):
        batch = [node.deposit() for _ in range(h % 4)]
        raws += batch
        node.add_block(node.T(h), batch)
    errors, done = [], threading.Event()

    def reader():
        try:
            while not done.is_set():
                t = ix.tip()
                ix.block(t)
                ix.utxo(txid(raws[0]), 0)
                ix.current_height()
        except Exception as e:      # pragma: no cover - reported below
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    try:
        for _ in range(3):
            ix.sync()
            node.add_block(node.blocks[-1]['timestamp'] + 2, [node.deposit()])
    finally:
        done.set()
        for t in threads:
            t.join()
    assert not errors
    check_chain(ix, node)


# ------------------------------------------------------------ catch-up of a fresh node (SPEC 5.2 ranges)

CATCHUP_BLOCKS = 86_000         # two days of Base Sepolia (2 s blocks) since DEPLOY_BLOCK


def long_chain(**kw):
    """A chain CATCHUP_BLOCKS past DEPLOY_BLOCK with a deposit every 5,000 blocks."""
    node = FakeChain(**kw)
    raws, t0 = [], node.T(1)
    for i in range(CATCHUP_BLOCKS):
        txs = [node.deposit()] if i % 5000 == 2500 else []
        raws += txs
        node.add_block(t0 + i, txs)
    return node, raws


def logs_ranges(node):
    return [(int(p[0]['fromBlock'], 16), int(p[0]['toBlock'], 16)) for m, p in node.calls if m == 'eth_getLogs']


def assert_caught_up(ix, node, raws):
    assert not ix.ibd and ix.tip() == ix.height_at(node.blocks[-2]['timestamp']) - 1
    assert all(ix.utxo(txid(r), 0) for r in raws)


@pytest.mark.parametrize('chunk,most', [(evm.LOGS_CHUNK, 9), (2000, 44)])
def test_catchup_on_a_10000_block_limit(tmp_path, monkeypatch, chunk, most):
    """Infura on Base Sepolia refuses ranges over 10,000 blocks (-32602
    "range N exceeds limit of 10000"). Ranges of 10,000: 9 calls for 86,000
    blocks, where ranges of 2,000 take 44."""
    monkeypatch.setattr(evm, 'LOGS_CHUNK', chunk)
    node, raws = long_chain(max_range=10_000)
    ix = fresh(tmp_path, node)
    assert ix.sync() is True
    assert node.count('eth_getLogs') == most
    assert_caught_up(ix, node, raws)


def test_catchup_adopts_a_smaller_stated_limit(tmp_path):
    node, raws = long_chain(max_range=4_000)
    ix = fresh(tmp_path, node)
    assert ix.sync() is True
    ranges = logs_ranges(node)
    assert ranges[0][1] - ranges[0][0] + 1 == 10_000            # refused once...
    assert all(b - a + 1 <= 4_000 for a, b in ranges[1:])       # ...then 4,000 at a time, remembered
    assert len(ranges) == 1 + 22 and node.logs_range_cap == 4_000
    assert_caught_up(ix, node, raws)


def test_catchup_with_some_429s(tmp_path):
    """Every 4th eth_getLogs answers HTTP 429: retried in place, 9 ranges
    plus 3 retries."""
    node, raws = long_chain(max_range=10_000, rate_limited=lambda n: n % 4 == 0)
    ix = fresh(tmp_path, node)
    assert ix.sync() is True
    assert 9 <= node.count('eth_getLogs') <= 12
    assert_caught_up(ix, node, raws)


def test_catchup_resumes_after_429s_give_up(tmp_path):
    """429s past request()'s retries fail the sync; the next one resumes from
    the last committed range, never from DEPLOY_BLOCK."""
    node, raws = long_chain(max_range=10_000, rate_limited=lambda n: 4 <= n <= 4 + node.rate_limit_retries)
    ix = fresh(tmp_path, node)
    with pytest.raises(evm.EvmError) as e:
        ix.sync()
    assert e.value.rate_limited and ix.ibd
    first = logs_ranges(node)
    done = first[:3]
    assert done[-1][1] == node.deploy_block + 30_000 - 1        # three ranges committed
    assert ix.tip() == 0                                        # no tip before the tag is reached
    node.calls.clear()
    node.rate_limited = None
    assert ix.sync() is True
    again = logs_ranges(node)
    assert again[0][0] == done[-1][1] + 1, 'resumed at the cursor'
    assert len(again) == 6
    assert_caught_up(ix, node, raws)
