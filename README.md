
```
Usage:
  spool2s3 [OPTIONS] DIRECTORY

Watch a directory, encrypt its files and spool them to an S3 bucket.

Spooling means that each successfully uploaded file is deleted.
Watching means that it gets notified by the kernel when new files are
created (e.g. via inotify on Linux). Thus, new files are immediately
uploaded.

For obvious reasons, new files should be copied into a sister
directory and then renamed or hard linked into the watched directory
(similar to how maildir works).

As a safety measure this program still traverses the watched
directory every --poll minutes in case a file creation event
got lost.

Files are encrypted using a GPG compatible symmetric encryption
algorithm and thus can be decrypted with e.g. 'gpg --decrypt-file ...'

2020, Georg Sauthoff <mail@gms.tf>, GPLv3+

Application Options:
  -v, --verbose         verbose output
  -b, --bucket=         S3 bucket name
      --url=URL         endpoint URL (default: s3.us-west-002.backblazeb2.com)
      --s3-key-id=      S3 key ID [$s3_key_id]
      --s3-key=         S3 key - supply it via an environment variable for
                        security reasons [$s3_key]
      --file-key=       file encryption key - supply it via an environment
                        variable for security reasons [$file_key]
      --poll=MINUTES    check every n minutes for new files in case a file
                        creation notification was lost (default: 15)

Help Options:
  -h, --help            Show this help message

Arguments:
  DIRECTORY:            directory to watch
```

## Build Instructions

On Fedora, you can install the build dependencies like this:

```
dnf install golang-github-coreos-systemd-devel \
        golang-github-fsnotify-devel \
        golang-github-jessevdk-flags-devel \
        golang-github-jsternberg-zap-logfmt-devel \
        golang-github-minio-devel \
        golang-uber-zap-devel
```

On other systems get the dependencies with `go get`.

Build with:

```
make
```
