import json

date = '20200227'

num_nodes = 40
num_epoch = 0
with open(f'collected_logs_{date}/pytest-node-bowenwang-0.txt') as f:
    for l in f:
        if 'Shard Tracker' in l and num_epoch <= 4:
            print(f'epoch: {num_epoch}')
            a = l.split('Shard Tracker: ')[-1]
            a = eval(a)
            #print(json.loads(a))
            #b = eval(b)
            #print(b)

            p = [0]*num_nodes
            e = [0]*num_nodes
            for k, c in a.items():
              for producer, (produced, expected) in c.items():
                  p[producer] += produced
                  e[producer] += expected
            ratio = [p[i] / e[i] if e[i] > 0 else 0 for i in range(num_nodes)]
            for i in range(num_nodes):
              print(f'node {i} produced {p[i]} expected {e[i]} ratio {(p[i] / e[i] if e[i] > 0 else 0):.2f}')
            print(f'max: {max(ratio):.2f} min: {min(ratio):.2f}')
            sorted_produced = sorted(p)
            median = (sorted_produced[num_nodes//2] + sorted_produced[num_nodes//2 + 1]) / 2
            print(len(list(filter(lambda x: x < median * 0.9, p))))
            num_epoch += 1
