# `tlx`

Simple utility to retrieve TLS certificate expiration dates.

## Installation / Update

```sh
go install github.com/andygeorge/tlx@latest
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
