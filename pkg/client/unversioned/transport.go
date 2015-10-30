/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package unversioned

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"k8s.io/kubernetes/pkg/client/transport"
	"k8s.io/kubernetes/pkg/util"
)

type userAgentRoundTripper struct {
	agent string
	rt    http.RoundTripper
}

func NewUserAgentRoundTripper(agent string, rt http.RoundTripper) http.RoundTripper {
	return &userAgentRoundTripper{agent, rt}
}

func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("User-Agent")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.Header.Set("User-Agent", rt.agent)
	return rt.rt.RoundTrip(req)
}

var _ = util.RoundTripperWrapper(&userAgentRoundTripper{})

func (rt *userAgentRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}

type basicAuthRoundTripper struct {
	username string
	password string
	rt       http.RoundTripper
}

// NewBasicAuthRoundTripper will apply a BASIC auth authorization header to a request unless it has
// already been set.
func NewBasicAuthRoundTripper(username, password string, rt http.RoundTripper) http.RoundTripper {
	return &basicAuthRoundTripper{username, password, rt}
}

func (rt *basicAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.SetBasicAuth(rt.username, rt.password)
	return rt.rt.RoundTrip(req)
}

var _ = util.RoundTripperWrapper(&basicAuthRoundTripper{})

func (rt *basicAuthRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}

type bearerAuthRoundTripper struct {
	bearer string
	rt     http.RoundTripper
}

// NewBearerAuthRoundTripper adds the provided bearer token to a request unless the authorization
// header has already been set.
func NewBearerAuthRoundTripper(bearer string, rt http.RoundTripper) http.RoundTripper {
	return &bearerAuthRoundTripper{bearer, rt}
}

func (rt *bearerAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}

	req = cloneRequest(req)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rt.bearer))
	return rt.rt.RoundTrip(req)
}

var _ = util.RoundTripperWrapper(&bearerAuthRoundTripper{})

func (rt *bearerAuthRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.rt
}

// TLSConfigFor returns a tls.Config that will provide the transport level security defined
// by the provided Config. Will return nil if no transport level security is requested.
func TLSConfigFor(config *Config) (*tls.Config, error) {
	return transport.TLSConfigFor(config.transportConfig())
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}
