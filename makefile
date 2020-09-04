

.PHONY: all
all: spool2s3


spool2s3: spool2s3.go
	GOPATH=$$HOME/go:/usr/share/gocode go build spool2s3.go
