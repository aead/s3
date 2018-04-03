[![Godoc Reference](https://godoc.org/github.com/aead/s3?status.svg)](https://godoc.org/github.com/aead/s3)
[![Build Status](https://travis-ci.org/aead/s3.svg?branch=master)](https://travis-ci.org/aead/s3)
[![Go Report Card](https://goreportcard.com/badge/aead/s3)](https://goreportcard.com/report/aead/s3)

## AWS S3 unit testing library

**S3** makes it possible to write AWS S3 unit tests and integrate them into
the Go development work-flow using the `go test` CLI.

**Install:** `go get github.com/aead/s3`

#### Run S3 tests

 1. Install minio S3 server: `go get -u github.com/minio/minio`
 2. Setup TLS:
    - `openssl ecparam -genkey -name prime256v1 | openssl ec -out ~/.minio/certs/private.key`
    - `openssl req -new -x509 -days 3650 -key ~/.minio/certs/private.key -out ~/.minio/certs/public.crt -subj "/C=US/ST=state/L=location/O=organization/CN=domain"`
 3. Run S3 server: `minio server <your-dir>`
 4. Run S3 tests: `go test -v -short github.com/aead/s3 -args -access=your-access-key -secret=your-secret-key -insecure`

#### Write S3 tests

```
import (
    "bytes"
    "crypto/tls"
    "net/http"
    "testing"

    "github.com/aead/s3"
    "github.com/minio/minio-go"
    "github.com/minio/minio-go/pkg/encrypt"
)

func TestEncryptedPut(t *testing.T) {
        if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}

	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})

	const bucket = "test-encrypted-put"
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	object, data, password := "object-1", make([]byte, 5*1024*1024), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+object))
	options := minio.PutObjectOptions{
		ServerSideEncryption: encryption,
	}

	if _, err = client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
		t.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
	}
	s3.RemoveObject(bucket, object, client.RemoveObject, t)
}
```
