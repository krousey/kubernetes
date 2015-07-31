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

package client

import (
	v1api "github.com/GoogleCloudPlatform/kubernetes/pkg/api/v1"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
)

// PodsNamespacer has methods to work with Pod resources in a namespace
type PodsNamespacer interface {
	Pods(namespace string) PodInterface
}

// PodInterface has methods to work with Pod resources.
type PodInterface interface {
	List(label labels.Selector, field fields.Selector) (*v1api.PodList, error)
	Get(name string) (*v1api.Pod, error)
	Delete(name string, options *v1api.DeleteOptions) error
	Create(pod *v1api.Pod) (*v1api.Pod, error)
	Update(pod *v1api.Pod) (*v1api.Pod, error)
	Watch(label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error)
	Bind(binding *v1api.Binding) error
	UpdateStatus(pod *v1api.Pod) (*v1api.Pod, error)
}

// pods implements PodsNamespacer interface
type pods struct {
	r  *Client
	ns string
}

// newPods returns a pods
func newPods(c *Client, namespace string) *pods {
	return &pods{
		r:  c,
		ns: namespace,
	}
}

// List takes label and field selectors, and returns the list of pods that match those selectors.
func (c *pods) List(label labels.Selector, field fields.Selector) (result *v1api.PodList, err error) {
	result = &v1api.PodList{}
	err = c.r.Get().Namespace(c.ns).Resource("pods").LabelsSelectorParam(label).FieldsSelectorParam(field).Do().Into(result)
	return
}

// Get takes the name of the pod, and returns the corresponding Pod object, and an error if it occurs
func (c *pods) Get(name string) (result *v1api.Pod, err error) {
	result = &v1api.Pod{}
	err = c.r.Get().Namespace(c.ns).Resource("pods").Name(name).Do().Into(result)
	return
}

// Delete takes the name of the pod, and returns an error if one occurs
func (c *pods) Delete(name string, options *v1api.DeleteOptions) error {
	// TODO: to make this reusable in other client libraries
	if options == nil {
		return c.r.Delete().Namespace(c.ns).Resource("pods").Name(name).Do().Error()
	}
	body, err := v1api.Codec.Encode(options)
	if err != nil {
		return err
	}
	return c.r.Delete().Namespace(c.ns).Resource("pods").Name(name).Body(body).Do().Error()
}

// Create takes the representation of a pod.  Returns the server's representation of the pod, and an error, if it occurs.
func (c *pods) Create(pod *v1api.Pod) (result *v1api.Pod, err error) {
	result = &v1api.Pod{}
	err = c.r.Post().Namespace(c.ns).Resource("pods").Body(pod).Do().Into(result)
	return
}

// Update takes the representation of a pod to update.  Returns the server's representation of the pod, and an error, if it occurs.
func (c *pods) Update(pod *v1api.Pod) (result *v1api.Pod, err error) {
	result = &v1api.Pod{}
	err = c.r.Put().Namespace(c.ns).Resource("pods").Name(pod.Name).Body(pod).Do().Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested pods.
func (c *pods) Watch(label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error) {
	return c.r.Get().
		Prefix("watch").
		Namespace(c.ns).
		Resource("pods").
		Param("resourceVersion", resourceVersion).
		LabelsSelectorParam(label).
		FieldsSelectorParam(field).
		Watch()
}

// Bind applies the provided binding to the named pod in the current namespace (binding.Namespace is ignored).
func (c *pods) Bind(binding *v1api.Binding) error {
	return c.r.Post().Namespace(c.ns).Resource("pods").Name(binding.Name).SubResource("binding").Body(binding).Do().Error()
}

// UpdateStatus takes the name of the pod and the new status.  Returns the server's representation of the pod, and an error, if it occurs.
func (c *pods) UpdateStatus(pod *v1api.Pod) (result *v1api.Pod, err error) {
	result = &v1api.Pod{}
	err = c.r.Put().Namespace(c.ns).Resource("pods").Name(pod.Name).SubResource("status").Body(pod).Do().Into(result)
	return
}
