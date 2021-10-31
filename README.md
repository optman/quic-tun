# quic-tun

A simple tcp port forwarding use QUIC as transport, based on [quinn](https://github.com/quinn-rs/quinn).

### Usage
Server Side:
```
$quic-tun gencert > /tmp/cert.pem
$quic-tun server -l 0.0.0.0:1080 -f target:80 -c /tmp/cert.pem -e 123456
...INFO  quic_tun] local:0.0.0.0:1080, forward:target:80, fingerprint: 2a92510d40
```

Client Side:
```
$quic-tun client -l 0.0.0.0:1080 -r server:1080 -p 2a92510d40 -e 123456
$curl localhost:1080
```

