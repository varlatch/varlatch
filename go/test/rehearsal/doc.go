// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

// Package rehearsal is step 7.8b's real-source rehearsal harness (internal
// docs/design/go-step7.md, slice 7.8; ADR-0059 amendment 10): `varlatch
// migrate` against a real Compose installation of the last TypeScript
// release (its images built from a checkout, by images.sh, while 0.23.0 is
// not published), where G5 (server/migration/g5) uses stand-ins.
//
// What is real here and stands in there: Docker and Compose, the
// TypeScript varlatchd (its barrier, marker, export, gate reader and
// evaluator) on PostgreSQL, its dashboard (stopped and started for the own
// proxy's port), Convex, and the TypeScript host CLI's backups to an S3
// server (MinIO). What stands in here too: systemd (the target varlatchd
// runs as this binary's child under the name systemctl, as in G5) and the
// operator's reverse proxy (a loopback proxy to the dashboard's port).
//
// It runs by hand, never in CI: run.sh builds the binaries and the images
// and runs this package's test binary on the host with Docker. Every
// container, network and volume it makes is named vl-rh-<run>-..., and is
// removed by that exact name at the end. Its report (report.json and
// report.md) holds no secret: the keys, the passwords, the run keys and
// the S3 credentials are generated per run and never written to it.
package rehearsal
