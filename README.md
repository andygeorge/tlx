# `tlx`

Simple utility to retrieve TLS certificate expiration dates.

## Installation / Update

```sh
# install go
sh -c 'VERSION="v1.0.0"; GH="github.com/andygeorge/tlx"; GOPRIVATE=$GH go install -v $GH@$VERSION'
```

## Usage

```sh
tlx DOMAIN [PORT]
```

eg:

```sh
$ tlx google.com
*.google.com expires 2023-06-26 08:17 UTC (in 53 days)
```
