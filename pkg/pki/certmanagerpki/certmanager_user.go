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
	"github.com/banzaicloud/kafka-operator/pkg/certutil"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/k8sutil"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FinalizeUserCertificate for cert-manager backend auto returns because controller references handle cleanup
func (c *certManager) FinalizeUserCertificate(user *v1alpha1.KafkaUser) (err error) { return }

func (c *certManager) ReconcileUserCertificate(user *v1alpha1.KafkaUser, scheme *runtime.Scheme) (userCert *pkicommon.UserCertificate, err error) {
	// See if we have an existing certificate for this user already
	cert, err := c.getUserCertificate(user)

	if err != nil && apierrors.IsNotFound(err) {
		// the certificate does not exist, let's make one
		cert = c.clusterCertificateForUser(user, scheme)
		if err = c.client.Create(context.TODO(), cert); err != nil {
			return userCert, errorfactory.New(errorfactory.APIFailure{}, err, "could not create user certificate")
		}

		controllerutil.SetControllerReference(c.cluster, user, scheme)
		if err = c.client.Update(context.TODO(), user); err != nil {
			return userCert, errorfactory.New(errorfactory.APIFailure{}, err, "could not update user with controller reference")
		}

	} else if err != nil {
		// API failure, requeue
		return userCert, errorfactory.New(errorfactory.APIFailure{}, err, "failed looking up user certificate")
	}

	secret, err := c.getUserSecret(user)
	if err != nil {
		return userCert, err
	}

	if user.Spec.IncludeJKS {
		if secret, err = certutil.EnsureSecretJKS(secret); err != nil {
			return userCert, errorfactory.New(errorfactory.InternalError{}, err, "could not inject secret with jks")
		}
		if err = c.client.Update(context.TODO(), secret); err != nil {
			return userCert, errorfactory.New(errorfactory.APIFailure{}, err, "could not update secret with jks")
		}
	}

	// Set Controller reference on user secret
	err = controllerutil.SetControllerReference(user, secret, scheme)
	if err != nil && !k8sutil.IsAlreadyOwnedError(err) {
		return userCert, errorfactory.New(errorfactory.InternalError{}, err, "error checking controller reference on user secret")
	} else if err == nil {
		if err = c.client.Update(context.TODO(), secret); err != nil {
			return userCert, errorfactory.New(errorfactory.APIFailure{}, err, "could not update secret with controller reference")
		}
	}

	userCert = &pkicommon.UserCertificate{
		CA:          secret.Data[v1alpha1.CoreCACertKey],
		Certificate: secret.Data[corev1.TLSCertKey],
		Key:         secret.Data[corev1.TLSPrivateKeyKey],
	}
	return userCert, nil
}

func (c *certManager) getUserCertificate(user *v1alpha1.KafkaUser) (*certv1.Certificate, error) {
	cert := &certv1.Certificate{}
	err := c.client.Get(context.TODO(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, cert)
	return cert, err
}

func (c *certManager) getUserSecret(user *v1alpha1.KafkaUser) (secret *corev1.Secret, err error) {
	secret = &corev1.Secret{}
	err = c.client.Get(context.TODO(), types.NamespacedName{Name: user.Spec.SecretName, Namespace: user.Namespace}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			err = errorfactory.New(errorfactory.ResourceNotReady{}, err, "user secret not ready")
		} else {
			err = errorfactory.New(errorfactory.APIFailure{}, err, "failed to get user secret")
		}
	}
	return
}

func (c *certManager) clusterCertificateForUser(user *v1alpha1.KafkaUser, scheme *runtime.Scheme) *certv1.Certificate {
	caName, caKind := c.getCA()
	cert := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      user.Name,
			Namespace: user.Namespace,
		},
		Spec: certv1.CertificateSpec{
			SecretName:  user.Spec.SecretName,
			KeyEncoding: certv1.PKCS8,
			CommonName:  user.Name,
			IssuerRef: certv1.ObjectReference{
				Name: caName,
				Kind: caKind,
			},
		},
	}
	controllerutil.SetControllerReference(user, cert, scheme)
	return cert
}

func (c *certManager) getCA() (caName, caKind string) {
	caKind = "ClusterIssuer"
	caName = fmt.Sprintf(pkicommon.BrokerIssuerTemplate, c.cluster.Name)
	return
}
