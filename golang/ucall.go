// Package ucall provides Go bindings for UCall, HTTP and Noise servers and clients over
// capability-specialized I/O backends.
//
// The package links the precompiled library and starts no goroutine: every handler runs on the
// goroutine polling the event loop or batch endpoint that received its request, and Example shows
// a server greeting a client.
//
// File: golang/ucall.go
// Author: Ash Vardanian
// Date: November 18, 2026
package ucall
