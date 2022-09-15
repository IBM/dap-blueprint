# How to use BIP32 key derivation on HPCS

## Prerequisites

Set HPCS access info into the following four environment variables

```
export HPCS_address="ep11.xxxxxxx.hs-crypto.cloud.ibm.com:xxxx"
export HPCS_APIKey="....................."
export HPCS_Endpoint="https://iam.cloud.ibm.com"
export HPCS_Instance="....................."
```

## Tested Scenarios

First, run an electrum daemon.

```
python3 run_electrum --testnet daemon
```

On another window, create a bip32hsm wallet. This takes a few minutes. Ignore a timeout error at client. Confirm the completion with a message from the daemon (e.g. `create_bip32hsm_wallet: write completed`).
The seed_type option can take `segwit` or `standard`. The default is `standard`. Segwit transactions seem to take longer to settle than standard ones.
```
python3 run_electrum --testnet create_bip32hsm {--seed_type standard}
```

Then, load the wallet and list addresses.
```
python3 run_electrum --testnet load_wallet
python3 run_electrum --testnet listaddresses
```

### One input and output

Pick the first address and send test bitcoins from another wallet. Then, confirm the balance.
```
python3 run_electrum --testnet getbalance
{
    "confirmed": "0",
    "unconfirmed": "0.0001"
}
```

Send back the entire balance to the source wallet. Then, get the transaction in hexadecimal and broadcast it.
```
python3 run_electrum --testnet payto tb1qy0v33svhexfe7cuy8m9zrrs0kjqqgf45qn3u9g !
02000000016690b66ac34ec56de131cd3d56a1af7063c578b6400f5cef707cef2df3a2c54d000000008a47304402207920345a4b7e504e96127638c89a076920bc00c4928f6c43a300377cb94a840e0220186ce36572a4f50089601c5b5c4b0c632dcdee086143eb20b72c56a986486cf1014104791df35c975ea28f6c4141371c771de7d2359884dd5a82c704820f34a1a7bde8e5a31b05310828d426ba0b9095c887b24db980b7188124176928900e8f68580efdffffff01332600000000000016001423d918c197c9939f63843eca218e0fb4800426b4870b1e00
python3 run_electrum --testnet broadcast 02000000016690b66ac34ec56de131cd3d56a1af7063c578b6400f5cef707cef2df3a2c54d000000008a47304402207920345a4b7e504e96127638c89a076920bc00c4928f6c43a300377cb94a840e0220186ce36572a4f50089601c5b5c4b0c632dcdee086143eb20b72c56a986486cf1014104791df35c975ea28f6c4141371c771de7d2359884dd5a82c704820f34a1a7bde8e5a31b05310828d426ba0b9095c887b24db980b7188124176928900e8f68580efdffffff01332600000000000016001423d918c197c9939f63843eca218e0fb4800426b4870b1e00
```

### Two inputs and one output

Similarly, send the second and third addresses from another wallet. Then, send them back at once.

This pattern requires two signatures to create one transaction since one transaction contains two addresses, each of which has a separate signing key.

```
python3 run_electrum --testnet payto tb1qy0v33svhexfe7cuy8m9zrrs0kjqqgf45qn3u9g !
0200000002613598ccbfe4cac31b8ef728a80b3a4378381709999cdbb1431edde8e717a25c000000008a47304402202a92ab453a86be89ddbcfc86476893a06ebc402249bb556f27a543271081e0560220727f7f0d77e1351e4ebba7da2c3dd60bbcf3c5c226044874086d1181fac8a4c6014104893ae9ca6d82cf5a610cc61bf50469da6b0a8bc0eba346011d76ab981b8fa6217c9f734cb90d16c8c4baa3547879f132928a16a8efa47467be2c3d4e42dc81d2fdffffffa37b7a9518c929d3801c95b248fb31e50d4094877843a3f1dc0bca94b4a479a8000000008b483045022100f5fc4a9f9a6caba942c39787367a6bdfddd79b8f126ee4c756e497509b970a7502202e814f26066fccee903ee4adb37a2e0d6e82a4437b54aaf4be84129cfe001b08014104d865b54b1c7ffa8f40a610907dfc6a20513174226c5c343b4fa4316ff6e8626575275f8a4b6e216eece6e82776c603e2511c7915030904772ca2df9e0a9ddac4fdffffff018f4c00000000000016001423d918c197c9939f63843eca218e0fb4800426b4640b1e00
python3 run_electrum --testnet broadcast 0200000002613598ccbfe4cac31b8ef728a80b3a4378381709999cdbb1431edde8e717a25c000000008a47304402202a92ab453a86be89ddbcfc86476893a06ebc402249bb556f27a543271081e0560220727f7f0d77e1351e4ebba7da2c3dd60bbcf3c5c226044874086d1181fac8a4c6014104893ae9ca6d82cf5a610cc61bf50469da6b0a8bc0eba346011d76ab981b8fa6217c9f734cb90d16c8c4baa3547879f132928a16a8efa47467be2c3d4e42dc81d2fdffffffa37b7a9518c929d3801c95b248fb31e50d4094877843a3f1dc0bca94b4a479a8000000008b483045022100f5fc4a9f9a6caba942c39787367a6bdfddd79b8f126ee4c756e497509b970a7502202e814f26066fccee903ee4adb37a2e0d6e82a4437b54aaf4be84129cfe001b08014104d865b54b1c7ffa8f40a610907dfc6a20513174226c5c343b4fa4316ff6e8626575275f8a4b6e216eece6e82776c603e2511c7915030904772ca2df9e0a9ddac4fdffffff018f4c00000000000016001423d918c197c9939f63843eca218e0fb4800426b4640b1e00
```

### One input and two outputs

Furthermore, send the fourth address from another wallet. Then send back the half amount. Such a payto transaction to send a partial amount causes additional key derivations, which cause a timeout at client. Get the transaction hexadecimal
from daemon debug prints.
```
python3 run_electrum --testnet getbalance
{
    "confirmed": "0",
    "unconfirmed": "0.0001"
}
python3 run_electrum --testnet payto tb1qavhu860dpqrwa096nqvanhk0c6kn4497mh2t77 0.00005
python3 run_electrum --testnet broadcast 02000000018bf873da97501e3d54363dbf8f4f916a419be978b734955f6a8312c2f283f4bc000000008b483045022100df73190e638db8d4c3ec11e5e45c1bddd285b96b7d3bdfc15f0f1dbab7c3c51102205445eda576f3d30ebb13431d59243869e0f8569d8bf7223fa31afae47dee3675014104ba594a8d47031a2ade2e24fe7fe20e73d293ca139f5019d3fcc22601188e275c860fde4b4fb63631d68ee8d493a11281b5d788795ce0ff4f24e5796d2479b6ebfdffffff0289120000000000001976a914a8d9e528015879f4a8d7a5b89d6ba4fe247d8f9388ac8813000000000000160014eb2fc3e9ed0806eebcba9819d9decfc6ad3ad4be8a0b1e00
```


## Useful links

- Bitcoin transaction decoder: https://live.blockcypher.com/btc-testnet/decodetx/ and https://btc.com/tools/tx/decode

- Bitcoin transaction constructor: https://tbtc.bitaps.com/constructor

- Blockchain browser: https://live.blockcypher.com
