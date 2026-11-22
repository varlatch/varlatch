// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// s3Server is the run's S3 server (MinIO, by digest), on loopback, its
// root credentials generated for the run and never written to the report.
type s3Server struct {
	name, endpoint string
	user, secret   string
}

const minioImage = "cgr.dev/chainguard/minio@sha256:e9cf6b99c226e9539ed0f14b6f00e37b07da153c7ba1f4f8709c807574b471ec"

func startS3(t *testing.T) *s3Server {
	t.Helper()
	s := &s3Server{name: "vl-rh-" + runID + "-minio", user: "rh" + hexBytes(6), secret: hexBytes(20)}
	port := freePort(t)
	must(t, run("", nil, nil, "docker", "run", "-d", "--name", s.name, "-p", "127.0.0.1:"+port+":9000",
		"-e", "MINIO_ROOT_USER="+s.user, "-e", "MINIO_ROOT_PASSWORD="+s.secret, minioImage, "server", "/data"), "start MinIO")
	t.Cleanup(func() {
		if os.Getenv("VL_RH_KEEP") != "1" {
			run("", nil, nil, "docker", "rm", "-fv", s.name)
		}
	})
	s.endpoint = "http://127.0.0.1:" + port
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		if resp, err := http.Get(s.endpoint + "/minio/health/ready"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("MinIO did not become ready")
		}
	}
}

// s3 runs one S3 operation through the TypeScript checkout's own client
// (its @aws-sdk/client-s3), so no other S3 tool is needed.
func (s *s3Server) s3(t *testing.T, op string, args ...string) ran {
	t.Helper()
	script := `
const { createRequire } = require("module");
const req = createRequire(process.env.VL_RH_TS + "/packages/backup/package.json");
const s3 = req("@aws-sdk/client-s3");
const client = new s3.S3Client({ endpoint: process.env.S3_ENDPOINT, region: "us-east-1", forcePathStyle: true,
  credentials: { accessKeyId: process.env.S3_USER, secretAccessKey: process.env.S3_SECRET } });
const [op, bucket, key, body] = process.argv.slice(1);
const run = async () => {
  if (op === "create-bucket") return client.send(new s3.CreateBucketCommand({ Bucket: bucket }));
  if (op === "delete-bucket") return client.send(new s3.DeleteBucketCommand({ Bucket: bucket }));
  if (op === "list") { const r = await client.send(new s3.ListObjectsV2Command({ Bucket: bucket })); console.log(JSON.stringify((r.Contents || []).map(o => o.Key))); return; }
  if (op === "put") return client.send(new s3.PutObjectCommand({ Bucket: bucket, Key: key, Body: Buffer.from(body, "base64") }));
  if (op === "get-size") { const r = await client.send(new s3.HeadObjectCommand({ Bucket: bucket, Key: key })); console.log(r.ContentLength); return; }
  if (op === "flip-byte") {
    const r = await client.send(new s3.GetObjectCommand({ Bucket: bucket, Key: key }));
    const b = Buffer.from(await r.Body.transformToByteArray());
    b[Math.floor(b.length / 2)] ^= 0xff;
    return client.send(new s3.PutObjectCommand({ Bucket: bucket, Key: key, Body: b }));
  }
  throw new Error("unknown op " + op);
};
run().catch(e => { console.error(e.name || e.message); process.exit(1); });`
	env := []string{"VL_RH_TS=" + tsCheckout, "S3_ENDPOINT=" + s.endpoint, "S3_USER=" + s.user, "S3_SECRET=" + s.secret}
	return run("", env, nil, "node", append([]string{"-e", script, op}, args...)...)
}

func (s *s3Server) createBucket(t *testing.T, bucket string) {
	t.Helper()
	must(t, s.s3(t, "create-bucket", bucket), "create bucket "+bucket)
}

func (s *s3Server) writeCredentials(t *testing.T, path string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"accessKeyId": s.user, "secretAccessKey": s.secret})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeDestination writes backup-destinations.json's "offsite" (the
// installation's prefix in bucket) and its write credentials beside it.
func (s *s3Server) writeDestination(t *testing.T, path, bucket, creds string) {
	t.Helper()
	s.writeCredentials(t, filepath.Join(filepath.Dir(path), creds))
	d := map[string]any{"offsite": map[string]any{"endpoint": s.endpoint, "region": "us-east-1", "bucket": bucket, "prefix": "rehearsal/",
		"forcePathStyle": true, "writeCredentialsFile": creds}}
	b, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// objects lists bucket's keys.
func (s *s3Server) objects(t *testing.T, bucket string) []string {
	t.Helper()
	r := must(t, s.s3(t, "list", bucket), "list "+bucket)
	var keys []string
	if err := json.Unmarshal([]byte(r.stdout), &keys); err != nil {
		t.Fatal(fmt.Errorf("list %s: %w", bucket, err))
	}
	return keys
}
