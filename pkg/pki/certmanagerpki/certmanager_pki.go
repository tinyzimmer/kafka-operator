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
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/k8sutil"
	"github.com/banzaicloud/kafka-operator/pkg/resources/templates"
	certutil "github.com/banzaicloud/kafka-operator/pkg/util/cert"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
	"github.com/go-logr/logr"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
				}
				if err := c.client.Delete(context.TODO(), cert); err != nil {
					return err
				}
			}

			// Might as well delete the secret and leave the controller reference earlier
			// as a safety belt
			secret := &corev1.Secret{}
			if err := c.client.Get(context.TODO(), obj, secret); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				if err := c.client.Delete(context.TODO(), secret); err != nil {
					return err
				}
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

		// I'm going to be lazy for now and make a copy in the format we expect
		// later during pod generation.
		bootSecret, passSecret, err := c.getBootstrapSSLSecret()
		if err != nil {
			return err
		}

		for _, o := range []*corev1.Secret{bootSecret, passSecret} {
			secret := &corev1.Secret{}
			if err := c.client.Get(context.TODO(), types.NamespacedName{Name: o.Name, Namespace: o.Namespace}, secret); err != nil {
				if apierrors.IsNotFound(err) {
					if err := c.client.Create(context.TODO(), o); err != nil {
						return errorfactory.New(errorfactory.APIFailure{}, err, "failed to create bootstrap secret")
					}
				} else {
					return errorfactory.New(errorfactory.APIFailure{}, err, "failed to lookup bootstrap secret")
				}
			}
		}

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
			} else {
				return errorfactory.New(errorfactory.InternalError{}, err, "failed to set controller reference on secret")
			}
		}
		if err := c.client.Update(context.TODO(), secret); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "failed to set controller reference on secret")
		}

	}

	return nil
}

func (c *certManager) kafkapki(scheme *runtime.Scheme) ([]runtime.Object, error) {
	rootCertMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster)
	rootCertMeta.Namespace = "cert-manager"

	if c.cluster.Spec.ListenersConfig.SSLSecrets.Create {
		// A self-signer for the CA Certificate
		selfsignerMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerSelfSignerTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster)
		selfsignerMeta.Namespace = metav1.NamespaceAll
		selfsigner := &certv1.ClusterIssuer{
			ObjectMeta: selfsignerMeta,
			Spec: certv1.IssuerSpec{
				IssuerConfig: certv1.IssuerConfig{
					SelfSigned: &certv1.SelfSignedIssuer{},
				},
			},
		}
		controllerutil.SetControllerReference(c.cluster, selfsigner, scheme)

		// The CA Certificate
		ca := &certv1.Certificate{
			ObjectMeta: rootCertMeta,
			Spec: certv1.CertificateSpec{
				SecretName: fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name),
				CommonName: fmt.Sprintf(pkicommon.CAFQDNTemplate, c.cluster.Name, c.cluster.Namespace),
				IsCA:       true,
				IssuerRef: certv1.ObjectReference{
					Name: fmt.Sprintf(pkicommon.BrokerSelfSignerTemplate, c.cluster.Name),
					Kind: "ClusterIssuer",
				},
			},
		}
		controllerutil.SetControllerReference(c.cluster, ca, scheme)
		// A cluster issuer backed by the CA certificate - so it can provision secrets
		// for producers/consumers in other namespaces
		clusterIssuerMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerIssuerTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster)
		clusterIssuerMeta.Namespace = metav1.NamespaceAll
		clusterissuer := &certv1.ClusterIssuer{
			ObjectMeta: clusterIssuerMeta,
			Spec: certv1.IssuerSpec{
				IssuerConfig: certv1.IssuerConfig{
					CA: &certv1.CAIssuer{
						SecretName: fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name),
					},
				},
			},
		}
		controllerutil.SetControllerReference(c.cluster, clusterissuer, scheme)

		// Broker "user"
		brokerUser := &v1alpha1.KafkaUser{
			ObjectMeta: templates.ObjectMeta(pkicommon.GetCommonName(c.cluster), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster),
			Spec: v1alpha1.KafkaUserSpec{
				SecretName: fmt.Sprintf(pkicommon.BrokerServerCertTemplate, c.cluster.Name),
				DNSNames:   pkicommon.GetDNSNames(c.cluster),
				IncludeJKS: true,
				ClusterRef: v1alpha1.ClusterReference{
					Name:      c.cluster.Name,
					Namespace: c.cluster.Namespace,
				},
			},
		}

		// Controller/Cruise-Control user for the cluster
		controllerUser := &v1alpha1.KafkaUser{
			ObjectMeta: templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerControllerTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster),
			Spec: v1alpha1.KafkaUserSpec{
				SecretName: fmt.Sprintf(pkicommon.BrokerControllerTemplate, c.cluster.Name),
				ClusterRef: v1alpha1.ClusterReference{
					Name:      c.cluster.Name,
					Namespace: c.cluster.Namespace,
				},
			},
		}

		return []runtime.Object{selfsigner, ca, clusterissuer, brokerUser, controllerUser}, nil

	}

	// If we aren't creating the secrets we need a cluster issuer made from the provided secret
	secret := &corev1.Secret{}
	err := c.client.Get(context.TODO(), types.NamespacedName{Namespace: c.cluster.Namespace, Name: c.cluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = errorfactory.New(errorfactory.ResourceNotReady{}, err, "could not find provided tls secret")
		} else {
			err = errorfactory.New(errorfactory.APIFailure{}, err, "could not lookup provided tls secret")
		}
		return []runtime.Object{}, err
	}
	caKey := secret.Data[v1alpha1.CAPrivateKeyKey]
	caCert := secret.Data[v1alpha1.CACertKey]

	caSecret := &corev1.Secret{
		ObjectMeta: templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster),
		Data: map[string][]byte{
			v1alpha1.CoreCACertKey:  caCert,
			corev1.TLSCertKey:       caCert,
			corev1.TLSPrivateKeyKey: caKey,
		},
	}
	controllerutil.SetControllerReference(c.cluster, caSecret, scheme)

	clusterIssuerMeta := templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerIssuerTemplate, c.cluster.Name), pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster)
	clusterIssuerMeta.Namespace = metav1.NamespaceAll
	clusterissuer := &certv1.ClusterIssuer{
		ObjectMeta: clusterIssuerMeta,
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{
					SecretName: fmt.Sprintf(pkicommon.BrokerCACertTemplate, c.cluster.Name),
				},
			},
		},
	}
	controllerutil.SetControllerReference(c.cluster, clusterissuer, scheme)

	return []runtime.Object{caSecret, clusterissuer}, nil

}

func (c *certManager) getBootstrapSSLSecret() (certs, passw *corev1.Secret, err error) {
	// get server (peer) certificate
	serverSecret := &corev1.Secret{}
	if err = c.client.Get(context.TODO(), types.NamespacedName{
		Name:      fmt.Sprintf(pkicommon.BrokerServerCertTemplate, c.cluster.Name),
		Namespace: c.cluster.Namespace,
	}, serverSecret); err != nil {
		if apierrors.IsNotFound(err) {
			err = errorfactory.New(errorfactory.ResourceNotReady{}, err, "server secret not ready")
			return
		}
		err = errorfactory.New(errorfactory.APIFailure{}, err, "could not get server cert")
		return
	}

	clientSecret := &corev1.Secret{}
	if err = c.client.Get(context.TODO(), types.NamespacedName{
		Name:      fmt.Sprintf(pkicommon.BrokerControllerTemplate, c.cluster.Name),
		Namespace: c.cluster.Namespace,
	}, clientSecret); err != nil {
		if apierrors.IsNotFound(err) {
			err = errorfactory.New(errorfactory.ResourceNotReady{}, err, "client secret not ready")
			return
		}
		err = errorfactory.New(errorfactory.APIFailure{}, err, "could not get client cert")
		return
	}

	certs = &corev1.Secret{
		ObjectMeta: templates.ObjectMeta(c.cluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName, pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster),
		Data: map[string][]byte{
			v1alpha1.CACertKey:           serverSecret.Data[v1alpha1.CoreCACertKey],
			v1alpha1.PeerCertKey:         serverSecret.Data[corev1.TLSCertKey],
			v1alpha1.PeerPrivateKeyKey:   serverSecret.Data[corev1.TLSPrivateKeyKey],
			v1alpha1.ClientCertKey:       clientSecret.Data[corev1.TLSCertKey],
			v1alpha1.ClientPrivateKeyKey: clientSecret.Data[corev1.TLSPrivateKeyKey],
		},
	}

	passw = &corev1.Secret{
		ObjectMeta: templates.ObjectMeta(c.cluster.Spec.ListenersConfig.SSLSecrets.JKSPasswordName, pkicommon.LabelsForKafkaPKI(c.cluster.Name), c.cluster),
		Data: map[string][]byte{
			v1alpha1.PasswordKey: certutil.GeneratePass(16),
		},
	}

	return
}
