
Before you begin, you need a repo you don't care about in github. It will be populated with branches and force pushed
often. It will be used to analyze your audit results.

- You must clone this repo locally. In this example, that repo is: ~/projects/test-audit/
- You must then specify a list of alias:hostname pairs to audit. The first host will be treated as the "canonical"
cluster against which all others will be compared. In this example, free-int will be treated as canon.
- You must specify strings that should be treated as equivalent between all clusters with -e tuples.

./oa.py master:scan-config -r ~/projects/test-audit/ free-int:54.147.205.250 free-stg:52.14.8.110 -e CLUSTER_NAME:free-int=free-stg -e SHARD:d800=1b7d

The follow invocation will push two new branches to github: free-int and free-stg. You can then
compare these with a URL like: https://github.com/jupierce/test-audit/compare/free-int...free-stg