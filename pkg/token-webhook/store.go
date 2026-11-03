/*
Copyright 2026 The Kubermatic Kubernetes Platform contributors.

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

package tokenwebhook

import (
	"context"
	"sync/atomic"
	"time"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// tokenSource is everything the authenticator needs from the seed caches.
// GetToken and GetAttribute return nil, nil when the object does not exist.
type tokenSource interface {
	GetToken(ctx context.Context, id string) (*kubermaticv1.UserClusterToken, error)
	GetAttribute(ctx context.Context, userID string) (*kubermaticv1.UserClusterAttribute, error)
	HasSynced() bool
	LastContact() time.Time
	CacheSizes() (tokens int, attributes int)
}

// informerState is the part of an informer the store reads.
type informerState interface {
	HasSynced() bool
}

// CacheStore serves UserClusterTokens and UserClusterAttributes from
// controller-runtime informer caches restricted to one namespace. It also
// tracks when the seed API was last reachable, either through a watch event
// or through a successful probe.
type CacheStore struct {
	namespace         string
	reader            ctrlruntimeclient.Reader
	tokenInformer     informerState
	attributeInformer informerState

	// contact holds the time of the last confirmed contact with the seed API.
	contact atomic.Pointer[time.Time]
}

// NewCacheStore returns a store reading through the given reader (the cached
// client of a cluster restricted to namespace) and the two informers. Events
// on the informers are registered by NewInformerStore; tests can inject
// plain informer states.
func NewCacheStore(namespace string, reader ctrlruntimeclient.Reader, tokenInformer, attributeInformer informerState) *CacheStore {
	return &CacheStore{
		namespace:         namespace,
		reader:            reader,
		tokenInformer:     tokenInformer,
		attributeInformer: attributeInformer,
	}
}

// MarkContact records that the seed API was reachable at t.
func (s *CacheStore) MarkContact(t time.Time) {
	s.contact.Store(&t)
}

// LastContact returns the time of the last confirmed API contact, or the
// zero time when there was none yet.
func (s *CacheStore) LastContact() time.Time {
	if t := s.contact.Load(); t != nil {
		return *t
	}
	return time.Time{}
}

// HasSynced is true once both informers finished their initial list.
func (s *CacheStore) HasSynced() bool {
	return s.tokenInformer.HasSynced() && s.attributeInformer.HasSynced()
}

// GetToken returns the token with the given ID (the object name), or nil
// when it does not exist.
func (s *CacheStore) GetToken(ctx context.Context, id string) (*kubermaticv1.UserClusterToken, error) {
	token := &kubermaticv1.UserClusterToken{}
	if err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: id}, token); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return token, nil
}

// GetAttribute returns the attribute of the given user (the object name is
// the KKP User name), or nil when it does not exist.
func (s *CacheStore) GetAttribute(ctx context.Context, userID string) (*kubermaticv1.UserClusterAttribute, error) {
	attribute := &kubermaticv1.UserClusterAttribute{}
	if err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.namespace, Name: userID}, attribute); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return attribute, nil
}

// CacheSizes returns the number of cached tokens and attributes.
func (s *CacheStore) CacheSizes() (int, int) {
	tokens := &kubermaticv1.UserClusterTokenList{}
	if err := s.reader.List(context.Background(), tokens, ctrlruntimeclient.InNamespace(s.namespace)); err != nil {
		return 0, 0
	}
	attributes := &kubermaticv1.UserClusterAttributeList{}
	if err := s.reader.List(context.Background(), attributes, ctrlruntimeclient.InNamespace(s.namespace)); err != nil {
		return len(tokens.Items), 0
	}
	return len(tokens.Items), len(attributes.Items)
}
