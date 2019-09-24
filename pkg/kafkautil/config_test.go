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

package kafkautil

import (
	"testing"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/pkg/pkiutil"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type mockClient struct {
	client.Client
}

func newMockCluster() *v1alpha1.KafkaCluster {
	cluster := &v1alpha1.KafkaCluster{}
	cluster.Name = "test"
	cluster.Namespace = "test"
	cluster.Spec = v1alpha1.KafkaClusterSpec{}
	cluster.Spec.ListenersConfig = v1alpha1.ListenersConfig{}
	cluster.Spec.ListenersConfig.InternalListeners = []v1alpha1.InternalListenerConfig{
		v1alpha1.InternalListenerConfig{ContainerPort: 80},
	}
	cluster.Spec.ListenersConfig.SSLSecrets = &v1alpha1.SSLSecrets{
		PKIBackend: pkiutil.MockBackend,
	}
	return cluster
}

func TestGenerateKafkaAddress(t *testing.T) {
	cluster := newMockCluster()
	cluster.Spec.HeadlessServiceEnabled = true
	generatedHeadless := generateKafkaAddress(cluster)
	expected := "test-headless.test:80"
	if generatedHeadless != expected {
		t.Error("Expected kafka address:", expected, "Got:", generatedHeadless)
	}

	cluster.Spec.HeadlessServiceEnabled = false
	generatedAllBroker := generateKafkaAddress(cluster)
	expected = "test-all-broker.test.svc.cluster.local:80"
	if generatedAllBroker != expected {
		t.Error("Expected kafka address:", expected, "Got:", generatedAllBroker)
	}
}

func TestClusterConfig(t *testing.T) {
	cluster := newMockCluster()
	_, err := ClusterConfig(&mockClient{}, cluster)
	if err != nil {
		t.Error("Expected no error got:", err)
	}
}
