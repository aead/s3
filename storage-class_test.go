// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.
package s3_test

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/aead/s3"
	minio "github.com/minio/minio-go"
)

var listObjectStorageClassTests = map[string]string{
	"object-0": "STANDARD",
	"object-1": "REDUCED_REDUNDANCY",
	"object-2": "", // expect default storage class
}

func TestListObjectStorageClass(t *testing.T) {
	if err := s3.Parse(); err != nil {
		t.Fatal(err)
	}
	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, !s3.NoTLS)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	if !s3.NoTLS {
		client.SetCustomTransport(&http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
		})
	}
	bucket := s3.BucketName("test-list-object-storage-class")
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		t.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(t)
	}

	data, i := make([]byte, s3.Size), 0
	for object, class := range listObjectStorageClassTests {
		options := minio.PutObjectOptions{StorageClass: class}
		if _, err = client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
			t.Fatalf("Test %d: Failed to upload object '%s/%s': %s", i, bucket, object, err)
		}
		defer s3.RemoveObject(bucket, object, client.RemoveObject, t)
		i++
	}

	doneCh := make(chan struct{})
	defer close(doneCh)
	const DefaultStorageClass = "STANDARD"
	for objInfo := range client.ListObjects(bucket, "", true, doneCh) {
		class, ok := listObjectStorageClassTests[objInfo.Key]
		if !ok {
			t.Errorf("Object '%s' was not uploaded", objInfo.Key)
			continue
		}
		if class == "" { // If not set expect default storage class (S3 behavior)
			class = DefaultStorageClass
		}
		if class != objInfo.StorageClass {
			t.Errorf("Object '%s' was not uploaded using storage class '%s' but was received with storage class '%s'", objInfo.Key, class, objInfo.StorageClass)
			continue
		}
		i--
	}
	if i != 0 {
		t.Errorf("Uploaded %d objects but ListObject showed only %d", len(listObjectStorageClassTests), len(listObjectStorageClassTests)-i)
	}
}
