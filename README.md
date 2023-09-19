# cert-collector
Script to collect all the possible certificate information from Satellite, Capsule and Content Host

It still under construction, but the main idea of usage it's something as mentioned below

- On your Satellite Server
```
# wget path_here
# ./cert-collector.sh --server
```
- On your Capsule Server
```
# wget path_here
# ./cert-collector.sh --capsule
```
- On your Content Host
```
# wget path_here
# ./cert-collector.sh --content_host
```

This should be enough to collect all the information we need and tell you which file should be shared/uploaded to the Support Case.