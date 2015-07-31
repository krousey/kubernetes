/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package client

import (
	v1api "github.com/GoogleCloudPlatform/kubernetes/pkg/api/v1"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
)

type SecretsNamespacer interface {
	Secrets(namespace string) SecretsInterface
}

type SecretsInterface interface {
	Create(secret *v1api.Secret) (*v1api.Secret, error)
	Update(secret *v1api.Secret) (*v1api.Secret, error)
	Delete(name string) error
	List(label labels.Selector, field fields.Selector) (*v1api.SecretList, error)
	Get(name string) (*v1api.Secret, error)
	Watch(label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error)
}

// events implements Secrets interface
type secrets struct {
	client    *Client
	namespace string
}

// newSecrets returns a new secrets object.
func newSecrets(c *Client, ns string) *secrets {
	return &secrets{
		client:    c,
		namespace: ns,
	}
}

func (s *secrets) Create(secret *v1api.Secret) (*v1api.Secret, error) {
	result := &v1api.Secret{}
	err := s.client.Post().
		Namespace(s.namespace).
		Resource("secrets").
		Body(secret).
		Do().
		Into(result)

	return result, err
}

// List returns a list of secrets matching the selectors.
func (s *secrets) List(label labels.Selector, field fields.Selector) (*v1api.SecretList, error) {
	result := &v1api.SecretList{}

	err := s.client.Get().
		Namespace(s.namespace).
		Resource("secrets").
		LabelsSelectorParam(label).
		FieldsSelectorParam(field).
		Do().
		Into(result)

	return result, err
}

// Get returns the given secret, or an error.
func (s *secrets) Get(name string) (*v1api.Secret, error) {
	result := &v1api.Secret{}
	err := s.client.Get().
		Namespace(s.namespace).
		Resource("secrets").
		Name(name).
		Do().
		Into(result)

	return result, err
}

// Watch starts watching for secrets matching the given selectors.
func (s *secrets) Watch(label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error) {
	return s.client.Get().
		Prefix("watch").
		Namespace(s.namespace).
		Resource("secrets").
		Param("resourceVersion", resourceVersion).
		LabelsSelectorParam(label).
		FieldsSelectorParam(field).
		Watch()
}

func (s *secrets) Delete(name string) error {
	return s.client.Delete().
		Namespace(s.namespace).
		Resource("secrets").
		Name(name).
		Do().
		Error()
}

func (s *secrets) Update(secret *v1api.Secret) (result *v1api.Secret, err error) {
	result = &v1api.Secret{}
	err = s.client.Put().
		Namespace(s.namespace).
		Resource("secrets").
		Name(secret.Name).
		Body(secret).
		Do().
		Into(result)

	return
}
