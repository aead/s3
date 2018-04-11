package s3_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/aead/s3"
	"github.com/minio/minio-go"
	"github.com/minio/minio-go/pkg/encrypt"
)

func BenchmarkEncryptedPut(b *testing.B) {
	if err := s3.Parse(); err != nil {
		b.Fatal(err)
	}
	if s3.NoTLS {
		b.Skip("Skipping benchmark because of -disableTLS flag")
	}

	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})

	bucket := s3.BucketName("bench-encrypted-put")
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		b.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(b)
	}

	object, data, password := "object-1", make([]byte, s3.Size), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+object))
	options := minio.PutObjectOptions{
		ServerSideEncryption: encryption,
	}
	if _, err = client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
		b.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
	}
	defer s3.RemoveObject(bucket, object, client.RemoveObject, b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err = client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
			b.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
		}
	}
}

func BenchmarkEncryptedGet(b *testing.B) {
	if err := s3.Parse(); err != nil {
		b.Fatal(err)
	}
	if s3.NoTLS {
		b.Skip("Skipping benchmark because of -disableTLS flag")
	}

	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})

	bucket := s3.BucketName("bench-encrypted-get")
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		b.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(b)
	}

	object, data, password := "object-1", make([]byte, s3.Size), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+object))
	options := minio.PutObjectOptions{
		ServerSideEncryption: encryption,
	}
	if _, err = client.PutObject(bucket, object, bytes.NewReader(data), int64(len(data)), options); err != nil {
		b.Fatalf("Failed to upload object '%s/%s': %s", bucket, object, err)
	}
	defer s3.RemoveObject(bucket, object, client.RemoveObject, b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		obj, err := client.GetObject(bucket, object, minio.GetObjectOptions{ServerSideEncryption: encryption})
		if err != nil {
			b.Fatalf("Failed to execute GET call for '%s/%s': %s", bucket, object, err)
		}
		if _, err = io.Copy(ioutil.Discard, obj); err != nil {
			b.Fatalf("Failed to download '%s/%s': %s", bucket, object, err)
		}
	}
}

func BenchmarkEncryptedCopy(b *testing.B) {
	if err := s3.Parse(); err != nil {
		b.Fatal(err)
	}
	if s3.NoTLS {
		b.Skip("Skipping benchmark because of -disableTLS flag")
	}

	client, err := minio.New(s3.Endpoint, s3.AccessKey, s3.SecretKey, true)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	client.SetCustomTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s3.Insecure},
	})

	bucket := s3.BucketName("bench-encrypted-copy")
	if remove, err := s3.MakeBucket(bucket, client.BucketExists, client.MakeBucket, client.RemoveBucket); err != nil {
		b.Fatalf("Failed to create bucket '%s': %s", bucket, err)
	} else {
		defer remove(b)
	}

	srcObject, dstObject, data, password := "object-1-src", "object-1-dst", make([]byte, s3.Size), "my-password"
	encryption := encrypt.DefaultPBKDF([]byte(password), []byte(bucket+srcObject+dstObject))
	options := minio.PutObjectOptions{
		ServerSideEncryption: encryption,
	}
	if _, err = client.PutObject(bucket, srcObject, bytes.NewReader(data), int64(len(data)), options); err != nil {
		b.Fatalf("Failed to upload object '%s/%s': %s", bucket, srcObject, err)
	}
	defer s3.RemoveObject(bucket, srcObject, client.RemoveObject, b)

	src := minio.NewSourceInfo(bucket, srcObject, encryption)
	dst, err := minio.NewDestinationInfo(bucket, dstObject, encryption, nil)
	if err != nil {
		b.Fatalf("Failed to create object destination '%s/%s': %s", bucket, dstObject, err)
	}
	if err = client.CopyObject(dst, src); err != nil {
		b.Fatalf("Failed to copy '%s/%s' to '%s/%s': %s", bucket, srcObject, bucket, dstObject, err)
	}
	defer s3.RemoveObject(bucket, dstObject, client.RemoveObject, b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err = client.CopyObject(dst, src); err != nil {
			b.Fatalf("Failed to copy '%s/%s' to '%s/%s': %s", bucket, srcObject, bucket, dstObject, err)
		}
	}
}
