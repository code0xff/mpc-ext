# Example dApp

A page that discovers the wallet over EIP-6963 and signs a message over EIP-1193. It contains no
mpc-ext-specific code, which is the point: any dApp that already speaks these standards works
unchanged.

## Running it

```bash
make build            # build the extension and the server
cargo run -p mpc-server   # with MPC_SERVER_SEALING_KEY set
python3 -m http.server -d examples/dapp 5173
```

Load `packages/extension/.output/chrome-mv3` as an unpacked extension, create a wallet in the
popup, then open <http://localhost:5173>.

Connecting asks for your approval once. Signing asks every time.
