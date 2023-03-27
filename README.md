# `tlx`

Simple utility to retrieve TLS certificate expiration dates.

### Installation

```sh
VERSION="v0.0.2"; GH="github.com/andygeorge/tlx"; GOPRIVATE=$GH go install -v $GH@$VERSION
```

### Usage

```sh
tlx DOMAIN [PORT]
```

eg:

```
$ tlx google.com
*.google.com expires 2023-05-29 (in 62 days)
```
