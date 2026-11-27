# evm-plugin

`evmbackend.py` is a Core Lightning backend plugin for Lightning channels on
an EVM chain. Core Lightning runs with `--network=regtest`, talks to this
plugin instead of `bcli`, and sees the
[UtxoChain contract](https://github.com/liquid-lightning/utxo-contract) as a
chain of Bitcoin blocks. The contract holds ETH, or one ERC-20 token, as a
Bitcoin-style UTXO set.

`SPEC.md` is the specification. It covers ETH on anvil (tests) and Base
Sepolia (testnet), and a token mode.

> **Status: MVP, not production ready.** This is a minimal build for
> testnets. It trusts the EVM node's logs: a node that lies or withholds logs
> is not detected. `SPEC.md` lists what the build leaves out. It has not been
> audited and must not be used with funds that matter.

## Requirements

- Core Lightning
- Python 3 with `pyln-client` and `coincurve`
- An EVM JSON-RPC endpoint and a deployed UtxoChain contract

## Run

```
lightningd --network=regtest --disable-plugin=bcli \
    --plugin=/path/to/evmbackend.py \
    --evm-rpc=<url> --evm-contract=<address>
```

`SPEC.md` section 5.6 lists the other CLN options the plugin expects, and
checks them after start.

| Option | Default | Meaning |
|---|---|---|
| `evm-rpc` | none | EVM JSON-RPC URL. A literal `${INFURA_API_KEY}` in it is read from the environment. |
| `evm-contract` | none | Address of the UtxoChain contract. |
| `evm-key-file` | `<lightning-dir>/evm-key` | File with this node's ETH key, created with mode 0600. |
| `evm-confirm` | `safe` | Confirmation tag: `safe` or `latest`. |
| `evm-poll` | 60 | Seconds between index polls (1 on anvil). |
| `evm-min-balance` | 0.01 | ETH balance below which new channels are refused. |

Keep API keys and the ETH key file out of the repository.

## RPC

Besides the five backend methods CLN calls (`getchaininfo`,
`getrawblockbyheight`, `getutxout`, `estimatefees`, `sendrawtransaction`):

| Method | What it does |
|---|---|
| `evm-deposit` | Deposits an amount from the node's ETH key into the contract, to an address |
| `evm-exitaddr` | Returns the address that a withdrawal pays out to a given ETH address |
| `evm-withdraw` | Withdraws the node key's withdrawable ETH or token from the contract |
| `evm-status` | Shows contract, chain, key, balances, tip, lag and alarms |

## Files

| Path | What |
|---|---|
| `evmbackend.py` | The plugin |
| `evmindex.py` | The index of the contract's events, kept in SQLite |
| `evm.py`, `btc.py` | EVM JSON-RPC and Bitcoin transaction helpers |
| `reference/` | An independent Python reference used to generate test cases |
| `gen_vectors.py` | Generates the contract's test vectors |
| `tests/` | Unit tests |
| `smoke_base_sepolia.py`, `smoke_forceclose.py` | Smoke tests against a live chain |

## Tests

`run-tests.sh` runs the unit tests and CLN integration tests on anvil in
Docker. It and some comments were written for the layout inside a CLN checkout
(`contrib/evmchan`). The developer edition runs the suites with
`./dev test evm-unit` and `./dev test evm`.

## Related repositories

- [utxo-contract](https://github.com/liquid-lightning/utxo-contract), the contract this plugin talks to
- [Core Lightning fork](https://github.com/MarkCherepovskyi/lightning)
- [swap-plugin](https://github.com/liquid-lightning/swap-plugin), for cross-asset payments
- [dashboard](https://github.com/liquid-lightning/dashboard), a web page for the nodes

## Licence

MIT, see [LICENSE](LICENSE).
