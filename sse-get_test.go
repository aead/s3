// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package s3_test

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strconv"
	"testing"

	"github.com/aead/s3"
	minio "github.com/minio/minio-go"
	"github.com/minio/minio-go/pkg/encrypt"
)

var encryptedGetTests = []struct {
	Type     encrypt.Type
	Password string
	KeyID    string
	Context  interface{}
}{
	{Type: encrypt.S3},
	{Type: encrypt.SSEC, Password: "my-password"},
}

func TestEncryptedGet(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	testEncryptedGet(s3.BucketName("test-encrypted-get"), s3.Size, t)
}

func TestEncryptedMultipartGet(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		t.Skip("Skipping test because of -short flag")
	}
	testEncryptedGet(s3.BucketName("test-encrypted-multipart-get"), s3.MultipartSize, t)
}

var encryptedRangeGetTests = []struct {
	Start, End int64
}{
	{Start: 0, End: s3.Size},           // 0
	{Start: 0, End: -s3.Size},          // 1
	{Start: s3.Size - 1, End: 0},       // 2
	{Start: 0, End: 0},                 // 3
	{Start: 1, End: s3.Size},           // 4
	{Start: 0, End: s3.Size / 2},       // 5
	{Start: s3.Size / 2, End: s3.Size}, // 6
}

func TestEncryptedRangeGet(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	bucket := s3.BucketName("test-encrypted-range-get")
	testEncryptedRangeGet(bucket, s3.Size, encryptedRangeGetTests, t)
}

var encryptedMultipartRangeGetTests = []struct {
	Start, End int64
}{
	{Start: 0, End: s3.MultipartSize},                    // 0
	{Start: 0, End: -s3.MultipartSize},                   // 1
	{Start: s3.MultipartSize - 1, End: 0},                // 2
	{Start: 0, End: 0},                                   // 3
	{Start: 1, End: s3.MultipartSize},                    // 4
	{Start: 0, End: s3.MultipartSize / 2},                // 5
	{Start: s3.MultipartSize / 2, End: s3.MultipartSize}, // 6
}

func TestEncryptedMultipartRangeGet(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		t.Skip("Skipping test because of -short flag")
	}
	bucket := s3.BucketName("test-encrypted-multipart-range-get")
	testEncryptedRangeGet(bucket, s3.MultipartSize, encryptedRangeGetTests, t)
}

func testEncryptedRangeGet(bucket string, size int64, tests []struct{ Start, End int64 }, t *testing.T) {
	if s3.NoTLS {
		t.Skip("Skipping test because of -disableTLS flag")
	}
	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})

	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	object, data, password := "object-1", make([]byte, size), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+object))
	options := minio.PutObjectOptions{ServerSideEncryption: encryption}
	if _, err := client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
		t.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
	}
	defer s3.RemoveObject(bucket, object, client.RemoveObject, t)

	for i, test := range tests {
		opts := minio.GetObjectOptions{ServerSideEncryption: encryption}
		opts.SetRange(test.Start, test.End)
		stream, err := client.GetObject(bucket, object, opts)
		if err != nil {
			t.Errorf("Test %d: Failed to open connection to '%s/%s/%s: %s", i, s3.Endpoint, bucket, object, err)
			continue
		}
		content, err := ioutil.ReadAll(stream)
		if err != nil {
			t.Errorf("Test %d: Failed get object '%s/%s': %s", i, bucket, object, err)
			continue
		}

		start := test.Start
		if test.Start < 0 {
			test.Start *= -1
		}
		if !bytes.Equal(content, data[start:start+int64(len(content))]) {
			t.Errorf("Test %d: Download object data does not match upload object data", i)
		}
	}
}

func testEncryptedGet(bucket string, size int64, t *testing.T) {
	if s3.NoTLS {
		t.Skip("Skipping test because of -disableTLS flag")
	}
	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	for i, test := range encryptedGetTests {
		object, data := "object-"+strconv.Itoa(i), make([]byte, size)
		var encryption encrypt.ServerSide
		switch test.Type {
		default:
			t.Errorf("Test %d: Unknown SSE type: %s", i, test.Type)
			continue
		case encrypt.S3:
			encryption = encrypt.NewSSE()
		case encrypt.SSEC:
			encryption = encrypt.DefaultPBKDF([]byte(test.Password), []byte(bucket+object))
		case encrypt.KMS:
			encryption, err = encrypt.NewSSEKMS(test.KeyID, test.Context)
			if err != nil {
				t.Errorf("Test %d: Failed to create KMS server side encryption: %s", i, err)
				continue
			}
		}
		options := minio.PutObjectOptions{ServerSideEncryption: encryption}
		n, err := client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options)
		if err != nil {
			t.Fatalf("Test %d: Failed to upload object '%s/%s': %s", i, bucket, object, err)
		}
		defer s3.RemoveObject(bucket, object, client.RemoveObject, t)
		if n != int64(len(data)) {
			t.Errorf("Test %d: Failed to complete object - object size: %d , uploaded: %d", i, len(data), n)
		}

		stream, err := client.GetObject(bucket, object, minio.GetObjectOptions{ServerSideEncryption: encryption})
		if err != nil {
			t.Errorf("Test %d: Failed to open connection to '%s/%s/%s: %s", i, s3.Endpoint, bucket, object, err)
			continue
		}
		content, err := ioutil.ReadAll(stream)
		if err != nil {
			t.Errorf("Test %d: Failed to get object %s/%s: %s", i, bucket, object, err)
			continue
		}
		if !bytes.Equal(data, content) {
			t.Errorf("Test %d: Download object does not match upload object", i)
		}
	}
}
