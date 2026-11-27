# Integration tests

`test_evmchan.py` and `evmchan_utils.py` run Core Lightning nodes on this
plugin against anvil.  They use CLN's pyln-testing fixtures, so they run
from a CLN checkout's `tests/` directory: devedition's build copies them
there (`./dev test evm`).  By hand: copy both files into `<lightning>/tests/`,
this plugin into `<lightning>/contrib/evmchan` and the contract into
`<lightning>/contracts/evm`, then `pytest tests/test_evmchan.py`.
