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
	"testing"

	"github.com/minio/minio-go"
)

func init() {
	flag.StringVar(&Endpoint, "server", "localhost:9000", "The S3 server endpoint.")
	flag.StringVar(&AccessKey, "access", "", "The S3 access key ID.")
	flag.StringVar(&SecretKey, "secret", "", "The S3 secret key.")

	flag.BoolVar(&Insecure, "insecure", false, "Skip TLS certificate checks.")
	flag.BoolVar(&NoTLS, "disableTLS", false, "Disable TLS. If set -insecure does nothing.")
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
