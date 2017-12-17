# ASAParser
Cisco ASA Log format to SQLite DB

This is a stand alone program to convert Cisco ASA logs to an SQLite DB, allowing for structed queries.

## Usage
-o SQLite outpute file (If not specified output to STDOUT)
-b SQLite commit buffer size (1024 is default)
-h help

### Examples
Output to file
```
cat cisco-asa.log | asap -b 2048 -o ./sqlite.db
```

Output to STDOUT
```
cat cisco-asa.log | asap -b 2048 
```

## Building
```
go get github.com/mattn/go-sqlite3
```
```
go build asap.go
```

