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

package certmanagerpki

import (
	"fmt"
	"reflect"

	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/go-logr/logr"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func reconcile(log logr.Logger, client client.Client, object runtime.Object, cluster *v1beta1.KafkaCluster) (err error) {
	switch object.(type) {
	case *certv1.ClusterIssuer:
		clusterIssuer, _ := object.(*certv1.ClusterIssuer)
		return reconcileClusterIssuer(log, client, clusterIssuer, cluster)
	case *certv1.Issuer:
		issuer, _ := object.(*certv1.Issuer)
		return reconcileIssuer(log, client, issuer, cluster)
	case *certv1.Certificate:
		cert, _ := object.(*certv1.Certificate)
		return reconcileCertificate(log, client, cert, cluster)
	case *corev1.Secret:
		secret, _ := object.(*corev1.Secret)
		return reconcileSecret(log, client, secret, cluster)
	default:
		panic(fmt.Sprintf("Invalid object type: %v", reflect.TypeOf(object)))
	}
}

func reconcileClusterIssuer(log logr.Logger, client client.Client, clusterIssuer *certv1.ClusterIssuer, cluster *v1beta1.KafkaCluster) (err error) {
	return
}

func reconcileIssuer(log logr.Logger, client client.Client, issuer *certv1.Issuer, cluster *v1beta1.KafkaCluster) (err error) {
	return
}

func reconcileCertificate(log logr.Logger, client client.Client, cert *certv1.Certificate, cluster *v1beta1.KafkaCluster) (err error) {
	return
}

func reconcileSecret(log logr.Logger, client client.Client, secret *corev1.Secret, cluster *v1beta1.KafkaCluster) (err error) {
	return
}
