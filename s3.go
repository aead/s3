// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package s3

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/minio/minio-go"
)

type sizeValue int64

func newSizeValue(val int64, p *int64) *sizeValue {
	*p = val
	return (*sizeValue)(p)
}

func (sv *sizeValue) Set(s string) error {
	const (
		B  = 1
		KB = 1024 * B
		MB = 1024 * KB
		GB = 1024 * MB
	)
	var (
		v   int64
		err error
	)
	switch upper := strings.ToUpper(s); {
	default:
		v, err = strconv.ParseInt(s, 10, 64)
		v *= B
	case strings.HasSuffix(upper, "GB"):
		v, err = strconv.ParseInt(s[:len(s)-2], 10, 64)
		v *= GB
	case strings.HasSuffix(upper, "MB"):
		v, err = strconv.ParseInt(s[:len(s)-2], 10, 64)
		v *= MB
	case strings.HasSuffix(upper, "KB"):
		v, err = strconv.ParseInt(s[:len(s)-2], 10, 64)
		v *= KB
	case strings.HasSuffix(upper, "B"):
		v, err = strconv.ParseInt(s[:len(s)-1], 10, 64)
		v *= B
	}
	if err != nil {
		return err
	}
	if v < 0 {
		v *= -1
	}
	*sv = sizeValue(v)
	return err
}

func (sv *sizeValue) Get() interface{} { return int64(*sv) }

func (sv *sizeValue) String() string { return strconv.FormatInt(int64(*sv), 10) }

func init() {
	flag.StringVar(&Endpoint, "server", "localhost:9000", "The S3 server endpoint.")
	flag.StringVar(&AccessKey, "access", "", "The S3 access key ID.")
	flag.StringVar(&SecretKey, "secret", "", "The S3 secret key.")

	flag.BoolVar(&Insecure, "insecure", false, "Skip TLS certificate checks.")
	flag.BoolVar(&NoTLS, "disableTLS", false, "Disable TLS. If set -insecure does nothing.")

	flag.Var(newSizeValue(32*1024, &Size), "size", "The object size for single part operations. Default: 32KB")
	flag.Var(newSizeValue(64*1024*1024, &MultipartSize), "sizeMultipart", "The object size for multipart part operations. Default: 65MB")
}

var (
	// Endpoint is the S3 endpoint. Specified either through the '-server' CLI argument
	// or through the 'SERVER_ENDPOINT' env. variable. The default is 'localhost:9000'
	Endpoint string
	// AccessKey is the S3 access-key for the specified endpoint. Specified either through
	// the '-access' CLI argument or through the 'ACCESS_KEY' env. variable.
	AccessKey string
	// SecretKey is the S3 secret-key for the specified endpoint. Specified either through
	// the '-secret' CLI argument or through the 'SECRET_KEY' env. variable.
	SecretKey string
	// Insecure allows TLS to endpoints without a valid signed TLS certificate.
	// Particually useful for local servers. Can be set using the '-insecure' CLI flag.
	Insecure bool
	// NoTLS disables TLS. All client requests will be made of plain HTTP/TCP connections.
	// Tests which require TLS will be skipped.
	NoTLS bool
	// Size is the size of objects for single-part operations in bytes. It is set by the '-size' CLI flag.
	Size int64
	// MultipartSize is the size of objects for multi-part operations in bytes. It is set by the '-sizeMultipart' CLI flag.
	MultipartSize int64
)

var (
	parsed   = false
	parseErr error
)

// Parse parses the command line arguments.
// It returns an error if no server, access-key
// or secret-key is provided and also no env.
// variables for the missing arguments are exported.
//
// It is save to call Parse() multiple times.
func Parse() error {
	if !parsed {
		parsed = true
		flag.Parse()

		var ok bool
		if Endpoint == "" {
			Endpoint, ok = os.LookupEnv("SERVER_ENDPOINT")
			if !ok {
				parseErr = errors.New("No server endpoint is provided and also no SERVER_ENDPOINT env. variable is exported")
				return parseErr
			}
		}
		if AccessKey == "" {
			AccessKey, ok = os.LookupEnv("ACCESS_KEY")
			if !ok {
				parseErr = errors.New("No access key is provided and also no ACCESS_KEY env. variable is exported")
				return parseErr
			}
		}
		if SecretKey == "" {
			SecretKey, ok = os.LookupEnv("SECRET_KEY")
			if !ok {
				parseErr = errors.New("No secret key is provided and also no SECRET_KEY env. variable is exported")
				return parseErr
			}
		}
		if Size == 0 {
			Size = 32 * 1024
		}
		if MultipartSize == 0 {
			MultipartSize = 65 * 1024 * 1024
		}
	}
	return parseErr
}

// BucketName returns a bucket name with the given
// prefix and a random hex suffix.
func BucketName(prefix string) string {
	var random [4]byte
	rand.Read(random[:])
	return prefix + "-" + hex.EncodeToString(random[:])
}

// MakeBucket checks whether the bucket exists, if not creates it
// and returns a function which removes the bucket if it was created successfully.
//
// It simplifies code that should cleanup created objects and buckets.
func MakeBucket(bucket string, exists func(string) (bool, error), make func(string, string) error, remove func(string) error) (func(testing.TB), error) {
	switch ok, err := exists(bucket); {
	case err != nil:
		return nil, err
	case !ok:
		if err = make(bucket, ""); err != nil {
			return nil, err
		}
		return func(t testing.TB) {
			if err := remove(bucket); err != nil {
				t.Errorf("Failed to remove bucket '%s': %s", bucket, err)
			}
		}, nil
	default:
		return func(testing.TB) {}, nil
	}
}

// ErrorCode returns the response code as string if
// the err is a minio.ErrorResponse. It returns
// a boolean flag indicating whether the provided error
// is a minio.ErrorResponse.
func ErrorCode(err error) (string, bool) {
	if errResp, ok := err.(minio.ErrorResponse); ok {
		return errResp.Code, ok
	}
	return "", false
}

// ErrorMessage returns the response message as string if
// the err is a minio.ErrorResponse. It returns
// a boolean flag indicating whether the provided error
// is a minio.ErrorResponse.
func ErrorMessage(err error) (string, bool) {
	if errResp, ok := err.(minio.ErrorResponse); ok {
		return errResp.Message, ok
	}
	return "", false
}

// RemoveObject removes the object at the bucket using the remove function.
// If the remove function returns a error RemoveObject() fails the test.
//
// It simplifies code that should cleanup created objects and buckets.
func RemoveObject(bucket, object string, remove func(bucket, object string) error, t testing.TB) {
	if err := remove(bucket, object); err != nil {
		t.Errorf("Failed to remove object '%s/%s': %s", bucket, object, err)
	}
}

// RemoveBucket removes the bucket using the remove function.
// If the remove function returns a error RemoveBucket() fails the test.
//
// It simplifies code that should cleanup created objects and buckets.
func RemoveBucket(bucket string, remove func(string) error, t testing.TB) {
	if err := remove(bucket); err != nil {
		t.Errorf("Failed to remove bucket '%s': %s", bucket, err)
	}
}
