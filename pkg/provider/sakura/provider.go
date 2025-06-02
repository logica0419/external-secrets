/*
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

package sakura

import (
	"context"
	"fmt"

	sakuraclient "github.com/sacloud/api-client-go"
	"github.com/sacloud/secretmanager-api-go"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/utils"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

// Register the provider with the external-secrets controller.
func init() {
	esv1.Register(&Provider{}, &esv1.SecretStoreProvider{
		Sakura: &esv1.SakuraProvider{},
	}, esv1.MaintenanceStatusMaintained)
}

type Provider struct{}

// Check if the Provider satisfies the esv1.Provider interface.
// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.Provider = &Provider{}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube client.Client, namespace string) (esv1.SecretsClient, error) {
	provider, err := getSakuraProvider(store)
	if err != nil {
		return nil, err
	}

	accessToken, err := resolvers.SecretKeyRef(ctx, kube, store.GetKind(), namespace, &provider.Auth.SecretRef.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve auth.secretRef.accessToken: %w", err)
	}
	accessTokenSecret, err := resolvers.SecretKeyRef(ctx, kube, store.GetKind(), namespace, &provider.Auth.SecretRef.AccessTokenSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve auth.secretRef.accessTokenSecret: %w", err)
	}

	client, err := secretmanager.NewClient(sakuraclient.WithApiKeys(accessToken, accessTokenSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to create Sakura Cloud client: %w", err)
	}

	return &Client{
		api: secretmanager.NewSecretOp(client, provider.VaultResourceID),
	}, nil
}

func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	prov, err := getSakuraProvider(store)
	if err != nil {
		return nil, err
	}

	if err := utils.ValidateReferentSecretSelector(store, prov.Auth.SecretRef.AccessToken); err != nil {
		return nil, fmt.Errorf("invalid Auth.SecretRef.AccessToken: %w", err)
	}
	if err := utils.ValidateReferentSecretSelector(store, prov.Auth.SecretRef.AccessTokenSecret); err != nil {
		return nil, fmt.Errorf("invalid Auth.SecretRef.AccessTokenSecret: %w", err)
	}

	return nil, nil
}
