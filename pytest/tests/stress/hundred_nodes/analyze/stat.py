date = '20200220'

num_epoch = 0
with open(f'/tmp/near/collected_logs_{date}/pytest-node-bowenwang-0.txt') as f:
    for l in f:
        if 'Num expected chunks' in l and num_epoch <= 4:
            print(f'epoch: {num_epoch}')
            a, b = l.split(', Num expected chunks ')
            a = a.split(', Shard Tracker: ')[-1]
            a = eval(a)
            b = eval(b)

            p = [0]*100
            e = [0]*100
            for k, c in a.items():
               for n in c.keys():
                   p[n] = c[n]
                   e[n] = b[k][n]
            ratio = [p[i] / e[i] if e[i] > 0 else 0 for i in range(100)]
            for i in range(100):
               print(f'node {i} produced {p[i]} expected {e[i]} ratio {(p[i] / e[i] if e[i] > 0 else 0):.2f}')
            print(f'max: {max(ratio):.2f} min: {min(ratio):.2f}')
            sorted_produced = sorted(p)
            median = (sorted_produced[49] + sorted_produced[50]) / 2
            print(len(list(filter(lambda x: x < median * 0.9, p))))
            num_epoch += 1
