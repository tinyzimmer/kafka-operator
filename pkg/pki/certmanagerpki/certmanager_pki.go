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
	"context"
	"fmt"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/k8sutil"
	"github.com/banzaicloud/kafka-operator/pkg/resources/templates"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
	"github.com/go-logr/logr"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (c *certManager) FinalizePKI(logger logr.Logger) error {
	logger.Info("Removing cert-manager certificates and secrets")

	// Safety check that we are actually doing something
	if c.cluster.Spec.ListenersConfig.SSLSecrets == nil {
		return nil
	}

	if c.cluster.Spec.ListenersConfig.SSLSecrets.Create {
		// Names of our certificates and secrets
		objNames := []types.NamespacedName{
			{Name: fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name), Namespace: "cert-manager"},
			{Name: fmt.Sprintf(pkicommon.BrokerServerCertTemplate, c.cluster.Name), Namespace: c.cluster.Namespace},
			{Name: fmt.Sprintf(pkicommon.BrokerControllerTemplate, c.cluster.Name), Namespace: c.cluster.Namespace},
		}
		for _, obj := range objNames {
			// Delete the certificates first so we don't accidentally recreate the
			// secret when it gets deleted
			cert := &certv1.Certificate{}
			if err := c.client.Get(context.TODO(), obj, cert); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				} else {
					return err
				}
			}
			if err := c.client.Delete(context.TODO(), cert); err != nil {
				return err
			}

			// Might as well delete the secret and leave the controller reference earlier
			// as a safety belt
			secret := &corev1.Secret{}
			if err := c.client.Get(context.TODO(), obj, secret); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				} else {
					return err
				}
			}
			if err := c.client.Delete(context.TODO(), secret); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *certManager) ReconcilePKI(logger logr.Logger, scheme *runtime.Scheme) (err error) {
	log := logger.WithName("certmanager_pki")

	resources, err := c.kafkapki(scheme)
	if err != nil {
		return err
	}

	for _, o := range resources {
		if err := reconcile(log, c.client, o, c.cluster); err != nil {
			return err
		}
	}

	if c.cluster.Spec.ListenersConfig.SSLSecrets.Create {

		// Grab ownership of CA secret for garbage collection
		secret := &corev1.Secret{}
		if err := c.client.Get(context.TODO(), types.NamespacedName{
			Name:      fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name),
			Namespace: "cert-manager",
		}, secret); err != nil {
			if apierrors.IsNotFound(err) {
				return errorfactory.New(errorfactory.ResourceNotReady{}, err, "pki secret not ready")
			}
			return errorfactory.New(errorfactory.APIFailure{}, err, "could not fetch pki secret")
		}
		if err := controllerutil.SetControllerReference(c.cluster, secret, scheme); err != nil {
			if k8sutil.IsAlreadyOwnedError(err) {
				return nil
			}
			return errorfactory.New(errorfactory.InternalError{}, err, "failed to set controller reference on secret")
		}
		if err := c.client.Update(context.TODO(), secret); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "failed to set controller reference on secret")
		}

	}

	return nil
}

func (c *certManager) kafkapki(scheme *runtime.Scheme) ([]runtime.Object, error) {

	if c.cluster.Spec.ListenersConfig.SSLSecrets.Create {
		// A self-signer for the CA Certificate
		selfsigner := selfSignerForCluster(c.cluster, scheme)

		// The CA Certificate
		ca := caCertForCluster(c.cluster, scheme)

		// A cluster issuer backed by the CA certificate - so it can provision secrets
		// for producers/consumers in other namespaces
		clusterissuer := mainIssuerForCluster(c.cluster, scheme)

		// Broker "user"
		brokerUser := pkicommon.BrokerUserForCluster(c.cluster)

		// Controller user
		controllerUser := pkicommon.ControllerUserForCluster(c.cluster)

		return []runtime.Object{selfsigner, ca, clusterissuer, brokerUser, controllerUser}, nil

	}

	// If we aren't creating the secrets we need a cluster issuer made from the provided secret
	caSecret, err := caSecretForProvidedCert(c.client, c.cluster, scheme)
	if err != nil {
		return nil, err
	}
	clusterissuer := mainIssuerForCluster(c.cluster, scheme)

	// Then finally broker/controller users from the imported CA
	// The client certificates in the secret will still work, however are not actually used.
	// This will also make sure that if the peerCert/clientCert provided are invalid
	// a valid one will still be used with the provided CA.
	// TODO: (tinyzimmer) - Would it be better to allow the KafkaUser to take a user-provided cert/key combination?
	brokerUser := pkicommon.BrokerUserForCluster(c.cluster)
	controllerUser := pkicommon.ControllerUserForCluster(c.cluster)
	return []runtime.Object{caSecret, clusterissuer, brokerUser, controllerUser}, nil

}

func caSecretForProvidedCert(client client.Client, cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := client.Get(context.TODO(), types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = errorfactory.New(errorfactory.ResourceNotReady{}, err, "could not find provided tls secret")
		} else {
			err = errorfactory.New(errorfactory.APIFailure{}, err, "could not lookup provided tls secret")
		}
		return nil, err
	}

	caKey := secret.Data[v1alpha1.CAPrivateKeyKey]
	caCert := secret.Data[v1alpha1.CACertKey]
	caSecret := &corev1.Secret{
		ObjectMeta: templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name), pkicommon.LabelsForKafkaPKI(cluster.Name), cluster),
		Data: map[string][]byte{
			v1alpha1.CoreCACertKey:  caCert,
			corev1.TLSCertKey:       caCert,
			corev1.TLSPrivateKeyKey: caKey,
		},
	}
	controllerutil.SetControllerReference(cluster, caSecret, scheme)
	return caSecret, nil
}

func selfSignerForCluster(cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) *certv1.ClusterIssuer {
	selfsignerMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerSelfSignerTemplate, cluster.Name), pkicommon.LabelsForKafkaPKI(cluster.Name), cluster)
	selfsignerMeta.Namespace = metav1.NamespaceAll
	selfsigner := &certv1.ClusterIssuer{
		ObjectMeta: selfsignerMeta,
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				SelfSigned: &certv1.SelfSignedIssuer{},
			},
		},
	}
	controllerutil.SetControllerReference(cluster, selfsigner, scheme)
	return selfsigner
}

func caCertForCluster(cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) *certv1.Certificate {
	rootCertMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name), pkicommon.LabelsForKafkaPKI(cluster.Name), cluster)
	rootCertMeta.Namespace = "cert-manager"
	ca := &certv1.Certificate{
		ObjectMeta: rootCertMeta,
		Spec: certv1.CertificateSpec{
			SecretName: fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name),
			CommonName: fmt.Sprintf(pkicommon.CAFQDNTemplate, cluster.Name, cluster.Namespace),
			IsCA:       true,
			IssuerRef: certv1.ObjectReference{
				Name: fmt.Sprintf(pkicommon.BrokerSelfSignerTemplate, cluster.Name),
				Kind: "ClusterIssuer",
			},
		},
	}
	controllerutil.SetControllerReference(cluster, ca, scheme)
	return ca
}

func mainIssuerForCluster(cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) *certv1.ClusterIssuer {
	clusterIssuerMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerIssuerTemplate, cluster.Name), pkicommon.LabelsForKafkaPKI(cluster.Name), cluster)
	clusterIssuerMeta.Namespace = metav1.NamespaceAll
	issuer := &certv1.ClusterIssuer{
		ObjectMeta: clusterIssuerMeta,
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{
					SecretName: fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name),
				},
			},
		},
	}
	controllerutil.SetControllerReference(cluster, issuer, scheme)
	return issuer
}
