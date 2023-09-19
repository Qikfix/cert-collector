# cert-collector
Script to collect all the possible certificate information from Satellite, Capsule and Content Host

# Disclaimer
This script doesn't intend to be supported or responsability of Red Hat, this is an independent initiative that will help for sure any Satellite case related to certs/ssl.

<br>

It still under construction, but the main idea of usage it's something as mentioned below:

- On your Satellite Server
```
# wget https://raw.githubusercontent.com/waldirio/cert-collector/main/cert-collector.sh
# ./cert-collector.sh --server
```
- On your Capsule Server
```
# wget https://raw.githubusercontent.com/waldirio/cert-collector/main/cert-collector.sh
# ./cert-collector.sh --capsule
```
- On your Content Host
```
# wget https://raw.githubusercontent.com/waldirio/cert-collector/main/cert-collector.sh
# ./cert-collector.sh --content_host
```

This should be enough to collect all the information we need and tell you which file should be shared/uploaded to the Support Case.