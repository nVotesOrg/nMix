### Benchmarks

|Date   |Trustees|Ballots    |Public key bits |Hardware**   |Heap   |Libmix opt.|Trustee opt.*|Time (min)
|---|---|---|---|---|---|---|---|---|
|3/21   |2   |3 x 100k   |2048   |2 x m4.16, 1 x m4.10   |5G|all |NNN|92
|3/25   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |NYN|72
|3/27   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYN|59
|5/20   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYN|58
|5/20   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYY|46
|5/23   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYY|43
|5/24   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYY|41
|5/24   |2   |3 x 300k   |2048   |2 x m4.16,1 x m4.10   |22G|all |YYY|121
|5/25   |2   |3 x 500k   |2048   |2 x m4.16,1 x m4.10   |36G|all |YYY|195

*The Trustee optimization settings column has the following syntax.
```
Permuted mix assignment=Y/N
Disable git compression=Y/N
Offline split=Y/N
```
Not all code changes and optimizations are reflected in this column.

**Hardware specs described in terms of [EC2 instance types](https://aws.amazon.com/ec2/instance-types/)