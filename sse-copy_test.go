// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package s3_test

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/aead/s3"
	"github.com/minio/minio-go/pkg/encrypt"

	minio "github.com/minio/minio-go"
)

func TestCustomerEncryptedCopy(t *testing.T) {
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
	const bucket = "test-customer-encrypted-copy"
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	// 1. Test SSE-C unencrypted -> encrypted copy
	srcObject, dstObject, data, password := "src-object-1", "dst-object-1", make([]byte, 5*1024*1024), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+dstObject))
	src := minio.NewSourceInfo(bucket, srcObject, nil)
	dst, err := minio.NewDestinationInfo(bucket, dstObject, encryption, nil)
	if err != nil {
		t.Fatalf("Failed to create destination: %s", err)
	}

	if _, err = client.PutObject(bucket, srcObject, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("Failed to create object '%s/%s': %s", bucket, srcObject, err)
	}
	defer s3.RemoveObject(bucket, srcObject, client.RemoveObject, t)
	if err = client.CopyObject(dst, src); err != nil {
		t.Fatalf("Failed to copy %s/%s to %s/%s: %s", bucket, srcObject, bucket, dstObject, err)
	}
	defer s3.RemoveObject(bucket, dstObject, client.RemoveObject, t)

	// 2. Test SSE-C encrypted -> encrypted copy
	srcObject, dstObject, password = dstObject, "dst-object-2", "my-password"
	src = minio.NewSourceInfo(bucket, srcObject, encryption)
	encryption = encrypt.DefaultPBKDF([]byte(password), []byte(bucket+dstObject))
	dst, err = minio.NewDestinationInfo(bucket, dstObject, encryption, nil)
	if err != nil {
		t.Fatalf("Failed to create destination: %s", err)
	}

	if err = client.CopyObject(dst, src); err != nil {
		t.Fatalf("Failed to copy %s/%s to %s/%s: %s", bucket, srcObject, bucket, dstObject, err)
	}
	defer s3.RemoveObject(bucket, dstObject, client.RemoveObject, t)

	// 3. Test SSE-C encrypted -> unencrypted copy
	srcObject, dstObject = dstObject, "dst-object-3"
	src = minio.NewSourceInfo(bucket, srcObject, encryption)
	dst, err = minio.NewDestinationInfo(bucket, dstObject, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create destination: %s", err)
	}

	if err = client.CopyObject(dst, src); err != nil {
		t.Fatalf("Failed to copy %s/%s to %s/%s: %s", bucket, srcObject, bucket, dstObject, err)
	}
	defer s3.RemoveObject(bucket, dstObject, client.RemoveObject, t)
}

var customerKeyRotationTests = []struct { // Tests are order-depended!
	Old, New   encrypt.ServerSide
	shouldFail bool
}{
	{Old: encrypt.DefaultPBKDF([]byte("my-passowrd"), []byte("my-salt")), New: mustNewSSEC(make([]byte, 32)), shouldFail: false}, // 0
	{Old: mustNewSSEC(make([]byte, 32)), New: mustNewSSEC(make([]byte, 32)), shouldFail: false},                                  // 1 // Equal keys
	{Old: mustNewSSEC(make([]byte, 32)), New: nil, shouldFail: false},                                                            // 2 // Server-Side decrypt
	{Old: nil, New: mustNewSSEC([]byte("32-byte SSE-C secret encryption.")), shouldFail: false},                                  // 3 // Server-Side encrypt
	{Old: nil, New: mustNewSSEC(make([]byte, 32)), shouldFail: true},                                                             // 4 // Wrong source key
	{Old: nil, New: nil, shouldFail: true},                                                                                       // 5 // Wrong source key- but src key == dst key == nil
	{Old: mustNewSSEC(make([]byte, 32)), New: mustNewSSEC(make([]byte, 32)), shouldFail: true},                                   // 6 // Wrong source key- but src key == dst key != nil See: https://github.com/minio/minio/issues/5625
}

func mustNewSSEC(key []byte) encrypt.ServerSide {
	sse, err := encrypt.NewSSEC(key)
	if err != nil {
		panic(err)
	}
	return sse
}

func TestCustomerKeyRotation(t *testing.T) {
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
	const bucket = "test-customer-key-rotation"
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	if len(customerKeyRotationTests) == 0 {
		t.Log("warning: no tests to run")
		return
	}
	object, data := "object-1", make([]byte, 5*1024*1024)
	options := minio.PutObjectOptions{ServerSideEncryption: customerKeyRotationTests[0].Old}
	if _, err := client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
		t.Fatalf("Failed to create object '%s/%s': %s", bucket, object, err)
	}
	defer s3.RemoveObject(bucket, object, client.RemoveObject, t)
	for i, test := range customerKeyRotationTests {
		src := minio.NewSourceInfo(bucket, object, test.Old)
		dst, err := minio.NewDestinationInfo(bucket, object, test.New, nil)
		if err != nil {
			t.Fatalf("Test %d: Failed to create destination: %s", i, err)
		}
		switch err = client.CopyObject(dst, src); {
		case err != nil && !test.shouldFail:
			t.Fatalf("Test %d: Failed to copy object from %s/%s to %s/%s: %s", i, bucket, object, bucket, object, err)
		case err == nil && test.shouldFail:
			t.Fatalf("Test %d: test should fail but passed successfully", i)
		}

		if !test.shouldFail {
			stream, err := client.GetObject(bucket, object, minio.GetObjectOptions{ServerSideEncryption: test.New})
			if err != nil {
				t.Fatalf("Failed to open connection to '%s/%s/%s: %s", s3.Endpoint, bucket, object, err)
			}
			content, err := ioutil.ReadAll(stream)
			if err != nil {
				t.Fatalf("Test %d: Failed to get object %s/%s: %s", i, bucket, object, err)
			}
			if !bytes.Equal(content, data) {
				t.Errorf("Test %d: Download object does not match upload object", i)
			}
		}
	}
}
