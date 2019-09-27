// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pki

import (
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	pkimanager "github.com/banzaicloud/kafka-operator/pkg/pki"
	"github.com/banzaicloud/kafka-operator/pkg/resources"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const componentName = "pki"

// Reconciler implements the Component Reconciler
type Reconciler struct {
	resources.Reconciler
	Scheme *runtime.Scheme
}

// New creates a new reconciler for a PKI
func New(client client.Client, scheme *runtime.Scheme, cluster *v1beta1.KafkaCluster) *Reconciler {
	return &Reconciler{
		Scheme: scheme,
		Reconciler: resources.Reconciler{
			Client:       client,
			KafkaCluster: cluster,
		},
	}
}

// Reconcile implements the reconcile logic for a kafka PKI
func (r *Reconciler) Reconcile(log logr.Logger) error {
	log = log.WithValues("component", componentName)

	if r.KafkaCluster.Spec.ListenersConfig.SSLSecrets == nil {
		log.Info("Skipping PKI reconciling due to no SSL config")
		return nil
	}

	log.Info("Reconciling PKI")

	if err := pkimanager.GetPKIManager(r.Client, r.KafkaCluster).ReconcilePKI(log, r.Scheme); err != nil {
		return err
	}

	log.Info("Reconciled")

	return nil
}
