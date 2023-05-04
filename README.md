# `tlx`

Simple utility to retrieve TLS certificate expiration dates.

### Installation

```sh
sh -c 'VERSION="v0.0.2"; GH="github.com/andygeorge/tlx"; GOPRIVATE=$GH go install -v $GH@$VERSION'
```

### Usage

```sh
tlx DOMAIN [PORT]
```

eg:

```
$ tlx google.com
*.google.com expires 2023-06-26 08:17 UTC (in 53 days)
```
