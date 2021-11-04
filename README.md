# quic-tun

A simple tcp port forwarding use QUIC as transport, based on [quinn](https://github.com/quinn-rs/quinn).

### Usage

1. map local port to remote

Server Side:
```
$quic-tun gencert > cert.pem
$quic-tun server -l 0.0.0.0:1080 -f target:80 -c cert.pem -e 123456
...local:0.0.0.0:1080, forward:target:80, fingerprint: 2a92510d40
...
```

Client Side:
```
$quic-tun client -l 0.0.0.0:80 -r server:1080 -p 2a92510d40 -e 123456
```

Test
```
$curl client:80
```

2. map remote port to local

Server Side:
```
$quic-tun gencert > cert.pem
$quic-tun server -l 0.0.0.0:1080  -c cert.pem -e 123456
...local:0.0.0.0:1080, fingerprint: 2a92510d40
```

Client Side:
```
$quic-tun client  -f target:80 -r server:1080 -o 80  -p 2a92510d40 -e 123456
```

Test
```
$curl server:80
```


