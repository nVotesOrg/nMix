![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)

### Benchmarks

|Date   |Trustees|Ballots    |Public key bits |Hardware**   |Heap   |Libmix opt.|Trustee opt.*|Time (min)
|---|---|---|---|---|---|---|---|---|
|3/21   |2   |3 x 100k   |2048   |2 x m4.16, 1 x m4.10   |5G|all |NNN|92
|3/25   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |NYN|72
|3/27   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYN|59
|5/20   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYN|58
|5/20   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYY|46
|5/20   |2   |3 x 200k   |2048   |2 x m4.16,1 x m4.10   |18G|all |YYY|
|5/20   |2   |3 x 200k   |2048   |2 x m4.16,1 x m4.10   |18G|all |YYN|

*The Trustee optimization settings column has the following syntax.
```
Permuted mix assignment=Y/N
Disable git compression=Y/N
Offline split=Y/N
```
Not all code changes and optimizations are reflected in this column.

**Hardware specs described in terms of [EC2 instance types](https://aws.amazon.com/ec2/instance-types/)