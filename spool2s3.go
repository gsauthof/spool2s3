package main

// SPDX-FileCopyrightText: © 2020 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later

import (
    "bytes"
    "errors"
    "io"
    "io/ioutil"
    // for fatal log messages until the real logger is set up
    "log"
    "os"
    "os/signal"
    "path"
    "syscall"
    "time"

    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/packet"

    "github.com/fsnotify/fsnotify"
    "github.com/jessevdk/go-flags"
    "github.com/minio/minio-go"
    "github.com/coreos/go-systemd/daemon"

    "go.uber.org/zap"
    _ "github.com/jsternberg/zap-logfmt"
)

type args struct {
    Verbosity []bool `short:"v" long:"verbose" description:"verbose output"`
    Positional struct {
        Dir string `positional-arg-name:"DIRECTORY" description:"directory to watch"`
    } `positional-args:"true" required:"true"`

    Bucket string `short:"b" long:"bucket" requried:"true" description:"S3 bucket name"`
    Endpoint string `long:"url" value-name:"URL" description:"endpoint URL" default:"s3.us-west-002.backblazeb2.com"`
    Key_id string `long:"s3-key-id" env:"s3_key_id" description:"S3 key ID"`
    Key string `long:"s3-key" env:"s3_key" description:"S3 key - supply it via an environment variable for security reasons"`

    File_key string `long:"file-key" env:"file_key" description:"file encryption key - supply it via an environment variable for security reasons"`

    Poll_min int `long:"poll" value-name:"MINUTES" default:"15" description:"check every n minutes for new files in case a file creation notification was lost"`

    Compress bool `long:"compress" short:"z" description:"compress files during encryption"`
}

func parse_args() *args {
    var args args
    p:= flags.NewParser(&args, flags.Default)
    p.LongDescription = `Watch a directory, encrypt its files and spool them to an S3 bucket.

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

2020, Georg Sauthoff <mail@gms.tf>, GPLv3+`
    _, err := p.Parse()

    if e, ok := err.(*flags.Error); ok {
	if e.Type == flags.ErrHelp {
	    os.Exit(0)
	} else {
            log.Fatal(err)
	    // os.Exit(1)
	}
    }

    if err != nil {
	log.Fatal(err)
    }

    if len(args.Key_id) == 0 {
	log.Fatal("key ID is missing")
    }
    if len(args.Key) == 0 {
	log.Fatal("key is missing")
    }
    if len(args.File_key) == 0 {
	log.Fatal("file encryption key is missing")
    }

    return &args
}

func create_logger(args *args) *zap.Logger {
    conf                            := zap.NewDevelopmentConfig()
    conf.Development                 = false
    conf.DisableCaller               = true
    conf.EncoderConfig.TimeKey       = "time"
    conf.EncoderConfig.LevelKey      = "level"
    conf.EncoderConfig.StacktraceKey = "stacktrace"
    conf.EncoderConfig.CallerKey     = "caller"
    conf.EncoderConfig.MessageKey    = "msg"
    conf.Encoding                    = "logfmt"

    l := zap.DebugLevel
    switch len(args.Verbosity) {
    case 0:
        l = zap.WarnLevel
    case 1:
        l = zap.InfoLevel
    }
    conf.Level = zap.NewAtomicLevelAt(l)

    logger, err := conf.Build()

    if err != nil {
	log.Fatal("Building zap logger configuration failed:", err)
    }

    return logger
}

func start_event_loop(sg *zap.SugaredLogger, watcher *fsnotify.Watcher, filenames chan string) {
    go func() {
    loop:
        for {
            select {
              case event, ok := <-watcher.Events:
                if !ok { // channel closed
                    break loop
                }
                if event.Op&fsnotify.Create == fsnotify.Create {
                    filenames <- event.Name
                }
              case err, ok := <-watcher.Errors:
                if !ok { // channel closed
                    break loop
                }
                sg.Warnf("fsevent error: %s", err)
            }
        }
        close(filenames)
    }()
}

func scan_dir(dir string, filenames chan string) int {
    fs, err := ioutil.ReadDir(dir)
    if err != nil {
        log.Fatal(err)
    }
    i := 0
    for _, f := range fs {
	filename := dir + "/" + f.Name()
        filenames <- filename
	i += 1
    }
    return i
}

func period_scan_dir(sg *zap.SugaredLogger, c <-chan time.Time, dir string, filenames chan string) {
    for {
        _, ok := <-c
        if !ok {
            return
        }
	sg.Debugw("Scanning directory on next time tick", "directory", dir)
	n := scan_dir(dir, filenames)
	sg.Debugw("Periodic directory scan done", "directory", dir,
                         "found", n)
    }
}

func encrypt(f io.Reader, file_key string, compress bool) (*bytes.Buffer, error) {

    ow := new(bytes.Buffer)

    calgo := packet.CompressionNone
    if compress {
	calgo = packet.CompressionZIP // gzip
    }

    iw, err := openpgp.SymmetricallyEncrypt(ow, []byte(file_key),
            &openpgp.FileHints { IsBinary: true },
	    &packet.Config {
		DefaultCompressionAlgo: calgo,
		// CompressionConfig: &packet.CompressionConfig{ Level: 9 },
	    })
    if err != nil {
	return nil, err
    }

    _, err = io.Copy(iw, f)
    if err != nil {
	iw.Close()
	return nil, err
    }

    err = iw.Close()
    if err != nil {
	return nil, err
    }

    return ow, nil
}


func encryptor(f io.Reader, file_key string, compress bool, w *io.PipeWriter, errc chan<- error) {

    calgo := packet.CompressionNone
    if compress {
	calgo = packet.CompressionZIP // gzip
    }

    iw, err := openpgp.SymmetricallyEncrypt(w, []byte(file_key),
            &openpgp.FileHints { IsBinary: true },
	    &packet.Config {
		DefaultCompressionAlgo: calgo,
		// CompressionConfig: &packet.CompressionConfig{ Level: 9 },
	    })
    if err != nil {
	w.CloseWithError(err)
	errc <-err
	return
    }

    _, err = io.Copy(iw, f)
    if err != nil {
	w.CloseWithError(err)
	iw.Close()
	errc <-err
	return
    }

    err = iw.Close()
    if err != nil {
	w.CloseWithError(err)
	errc <-err
	return
    }

    err = w.Close()
    if err != nil {
	errc <-err
	return
    }
    errc <-nil
}

func mk_obj_name(hostname string, label string) string{
    if ! path.IsAbs(label) {
	hostname += "/"
    }

    name := hostname + label

    return name
}

func spooler(sg *zap.SugaredLogger, done chan bool, filenames chan string, file_key string, compress bool, client *minio.Client, bucket string) {
    hostname, err := os.Hostname()
    if err != nil {
	sg.Fatalw("Can't get hostname", "err", err)
    }
    put_opts := minio.PutObjectOptions{ContentType: "application/octet-stream"}

    for {
	remove_file := false

        filename, ok := <-filenames
        if !ok { // channel closed
            close(done)
            return
        }
        sg.Debugw("Spooling next file", "filename", filename)

	name := mk_obj_name(hostname, filename)

	f, err := os.Open(filename)
	if err != nil {
	    sg.Errorw("Can't open file", "filename", filename, "err", err)
	    continue
	}
        st, err := f.Stat()
	if err != nil  {
	    sg.Errorw("Can't stat file", "filename", filename, "err", err)
	    f.Close()
	    continue
	}

	// stream if file is large - otherwise the it's better to
	// encrypt it into a temporary buffer because then we
	// can use the atomic S3 put with minio which requires much less
	// memory
	if st.Size() >= 128 * 1024 * 1024 {
	    pr, pw := io.Pipe()

	    enc_err_c := make(chan error)
	    go encryptor(f, file_key, compress, pw, enc_err_c)

            n, err := client.PutObject(bucket, name, pr, -1, put_opts)

	    // make sure that encryptor terminates in case not real all writes
	    // were consumed by upload_file - if they were this is a NOP
	    pr.CloseWithError(errors.New("upload didn't read everything"))

	    enc_err := <-enc_err_c
	    if enc_err != nil {
		sg.Errorw("Encryption failed", "filename", filename, "err", enc_err)
	    }
	    if err == nil {
		sg.Infow("Uploaded file:", "filename", filename, "size", n)
		remove_file = true
	    } else {
		sg.Errorw("Upload failed", "filename", filename, "err", err)
	    }

        } else {
	    br, err := encrypt(f, file_key, compress)
	    if err != nil {
		sg.Errorw("Encryption failed", "filename", filename, "err", err)
	    } else {
                n, err := client.PutObject(bucket, name, br, int64(br.Len()), put_opts)
		if  err != nil {
		    sg.Errorw("Upload failed", "filename", filename, "err", err)
		} else {
		    sg.Infow("Uploaded file:", "filename", filename, "size", n)
		    remove_file = true
		}
	    }
	}

	err = f.Close()
	if err != nil {
	    sg.Errorw("Error closing file", "filename", filename, "err", err)
	} else {
	    if remove_file {
		err = os.Remove(filename)
		if err != nil {
		    sg.Errorw("Removing input file failed", "filename", filename,
			      "err", err)
		}
	    }
	}


    }
}

func mk_dir_watcher(dir string) (*fsnotify.Watcher, error) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
	return nil, err
    }

    err = watcher.Add(dir)
    if err != nil {
	watcher.Close()
	return nil, err
    }
    return watcher, nil
}

func mk_sig_chan() chan os.Signal {
    signals := make(chan os.Signal, 1)
    signal.Notify(signals, os.Interrupt)
    signal.Notify(signals, syscall.SIGTERM)
    return signals
}

func main() {
    args   := parse_args()
    dir    := args.Positional.Dir
    lg     := create_logger(args)
    defer lg.Sync()
    sg     := lg.Sugar()

    client, err := minio.New(args.Endpoint, args.Key_id, args.Key, true)
    if err != nil {
        sg.Fatalw("Can't connect", "err", err, "endpoint", args.Endpoint,
                        "key_id", args.Key_id)
    }

    watcher, err := mk_dir_watcher(dir)
    if err != nil {
	sg.Fatalw("Creating directory watch failed", "directory", dir, "err", err)
    }
    defer watcher.Close()

    daemon.SdNotify(false, daemon.SdNotifyReady)

    sg.Infow("Watching directory", "directory", dir)

    ticker := time.NewTicker(time.Duration(args.Poll_min) * time.Minute)
    defer ticker.Stop()

    done      := make(chan bool)
    filenames := make(chan string)
    start_event_loop(sg, watcher, filenames)
    go spooler(sg, done, filenames, args.File_key, args.Compress, client, args.Bucket)

    go period_scan_dir(sg, ticker.C, dir, filenames)

    signals := mk_sig_chan()

    go func() {
        <-signals
        ticker.Stop()
        err := watcher.Close()
        if err != nil {
	    sg.Fatalw("Closing directory watcher failed", "err", err)
        }
    }()

    scan_dir(dir, filenames)

    <-done

}
