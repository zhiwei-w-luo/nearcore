# The test launches two validating node and two observers
# The first observer tracks no shards, the second observer tracks all shards
# The second observer is used to query balances
# We then send one transaction synchronously through the first observer, and expect it to pass and apply due to rpc tx forwarding

import sys, time, base58, random

sys.path.append('lib')


from cluster import start_cluster
from utils import TxContext
from transaction import sign_payment_tx

nodes = start_cluster(2, 2, 4, {'local': True, 'near_root': '../target/debug/'}, [["gas_price", 0], ["epoch_length", 10], ["block_producer_kickout_threshold", 70]], {2: {"tracked_shards": [0, 1, 2, 3]}})

time.sleep(5)

status = nodes[0].get_status()
latest_block_hash = status['sync_info']['latest_block_hash']

for i in range(4):
    tx = sign_payment_tx(nodes[i].signer_key, 'test%s' % (i+1 % 4), 100, 1, base58.b58decode(latest_block_hash.encode('utf8')))
    print("sending transaction from node%s" % i)
    nodes[-1].send_tx_and_wait(tx, timeout=10)

for i in range(4):
    query_result1 = nodes[-2].get_account("test%s" % i)
    query_result2 = nodes[-1].get_account("test%s" % i)
    assert query_result1 == query_result2, "query same account gives different result"
