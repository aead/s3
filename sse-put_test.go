// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package s3_test

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"

	"github.com/aead/s3"
	"github.com/minio/minio-go"
	"github.com/minio/minio-go/pkg/encrypt"
)

var encryptedPutTests = []struct {
	Type     encrypt.Type
	Password string
	KeyID    string
	Context  interface{}
}{
	{Type: encrypt.S3},
	{Type: encrypt.SSEC, Password: "my-password"},
	{Type: encrypt.KMS, KeyID: "", Context: nil},
}

func TestEncryptedPut(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	testEncryptedPut(s3.BucketName("test-encrypted-put"), 5*1024*1024, t)
}

func TestEncryptedMultipartPut(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		t.Skip("Skipping test because of -short flag")
	}
	testEncryptedPut(s3.BucketName("test-encrypted-multipart-put"), 69*1024*1024, t)
}

func testEncryptedPut(bucket string, size int, t *testing.T) {
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

	for i, test := range encryptedPutTests {
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
			t.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
		}
		defer s3.RemoveObject(bucket, object, client.RemoveObject, t)
		if n != int64(len(data)) {
			t.Errorf("Failed to complete object - object size: %d , uploaded: %d", len(data), n)
		}
	}
}

func TestEncryptedObjectEtag(t *testing.T) {
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

	bucket := s3.BucketName("test-encrypted-object-etag")
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
	defer s3.RemoveObject(bucket, object, client.RemoveObject, t)

	info, err := client.StatObject(bucket, object, minio.StatObjectOptions{
		GetObjectOptions: minio.GetObjectOptions{
			ServerSideEncryption: encryption,
		},
	})
	if err != nil {
		t.Fatalf("Failed to receive object info of '%s/%s': %s", bucket, object, err)
	}
	if md5Sum := md5.Sum(data); hex.EncodeToString(md5Sum[:]) == info.ETag {
		// This check might fail because the ETag - which is chosen randomly by the S3
		// server - could be equal to the content-MD5 randomly. If this tests fails run
		// it again. Only if this test keeps failing it indicates a bug in the server.
		t.Error("Content-MD5 must not match etag for SSE-C encrypted objects")
	}
}
