import json

date = '20200305'

num_nodes = 100
num_epoch = 0
with open(f'/tmp/near/collected_logs_{date}/pytest-node-bowenwang-1.txt') as f:
    for l in f:
        if 'Shard Tracker' in l:
            print(f'epoch: {num_epoch}')
            [a, b] = l.split('Shard Tracker: ')
            a = a.split('Block Tracker: ')[-1]
            a = eval(a)[0]
            b = eval(b)
            print('Blocks:')
            print('--------')
            for node in sorted(list(a.keys())):
                produced, expected = a[node]
                print(f'node {node} produced {produced} expected {expected}')
            p = [0]*num_nodes
            e = [0]*num_nodes
            for k, c in b.items():
              for producer, (produced, expected) in c.items():
                  p[producer] += produced
                  e[producer] += expected
            ratio = [p[i] / e[i] if e[i] > 0 else 0 for i in range(num_nodes)]
            print('Chunks:')
            print('-------')
            for i in range(num_nodes):
              print(f'node {i} produced {p[i]} expected {e[i]} ratio {(p[i] / e[i] if e[i] > 0 else 0):.2f}')
            ratio = list(filter(lambda x: x > 0, ratio))
            print(f'max: {max(ratio):.2f} min: {min(ratio):.2f}')
            sorted_produced = sorted(p)
            median = (sorted_produced[num_nodes//2] + sorted_produced[num_nodes//2 + 1]) / 2
            print(len(list(filter(lambda x: x < median * 0.9, p))))
            num_epoch += 1
