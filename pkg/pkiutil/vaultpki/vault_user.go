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

package vaultpki

import (
	"fmt"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/pkg/certutil"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/pkiutil/pkicommon"
	vaultapi "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (v *vaultPKI) ReconcileUserCertificate(user *v1alpha1.KafkaUser, scheme *runtime.Scheme) (*pkicommon.UserCertificate, error) {
	client, err := v.getClient()
	if err != nil {
		return nil, err
	}

	certs, err := v.list(client, v.getUserStorePath())
	if err != nil {
		return nil, err
	}

	caCert, err := v.getCA(client)
	if err != nil {
		return nil, err
	}

	var userSecret *vaultapi.Secret
	var userCert *pkicommon.UserCertificate
	if contains(certs, sanitizedResourceUid(user.GetUID())) {
		userSecret, err = client.Logical().Read(
			fmt.Sprintf("%s/%s", v.getUserStorePath(), sanitizedResourceUid(user.GetUID())),
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to retrieve user certificate")
		}
		userCert = rawToCertificate(userSecret.Data, caCert)
	} else {
		userSecret, err = client.Logical().Write(
			v.getIssuePath(),
			map[string]interface{}{
				"common_name":          user.Name,
				"ttl":                  "60000h",
				"private_key_format":   "pkcs8",
				"exclude_cn_from_sans": true,
			},
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to create user certificate")
		}
		userCert = rawToCertificate(userSecret.Data, caCert)
		_, err = client.Logical().Write(
			fmt.Sprintf("%s/%s", v.getUserStorePath(), sanitizedResourceUid(user.GetUID())),
			userSecret.Data,
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to store user certificate")
		}
	}

	if err = ensureVaultSecret(client, userCert, user); err != nil {
		return nil, err
	}

	return userCert, nil
}

func ensureVaultSecret(client *vaultapi.Client, userCert *pkicommon.UserCertificate, user *v1alpha1.KafkaUser) error {
	storePath := user.Spec.SecretName

	mountPath, v2, err := isKVv2(storePath, client)
	if err != nil {
		return err
	} else if v2 {
		storePath = addPrefixToVKVPath(storePath, mountPath, "data")
	}

	var present *vaultapi.Secret

	// Check if we have an existing user secret
	if present, err = client.Logical().Read(storePath); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "could not check for existing user secret")
	}

	if present != nil {
		// "de-serialize" the existing vault secret
		presentCert, err := userCertForData(present.Data)
		if err != nil {
			return errorfactory.New(errorfactory.InternalError{}, err, "could not parse stored user secret")
		}
		// make sure the stored certificate matches the one we have
		if certificatesMatch(presentCert, userCert) {
			// We have an existing secret stored that matches the provided one
			// we'll use that going forward to re-use a JKS if present
			userCert = presentCert
		}
	}

	// Ensure a JKS if requested
	if user.Spec.IncludeJKS {
		// we don't have an existing one - make a new one
		if userCert.JKS == nil {
			userCert.JKS, userCert.Password, err = certutil.GenerateJKS(userCert.Certificate, userCert.Key, userCert.CA)
			if err != nil {
				return errorfactory.New(errorfactory.InternalError{}, err, "failed to generate JKS from user certificate")
			}
		}
	}

	// Write any changes back to the vault backend
	if _, err = client.Logical().Write(storePath, newVaultSecretData(v2, userCert)); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to store secret to user provided location")
	}
	return nil
}

func newVaultSecretData(isV2 bool, cert *pkicommon.UserCertificate) map[string]interface{} {
	if isV2 {
		return map[string]interface{}{
			"data":    dataForUserCert(cert),
			"options": map[string]interface{}{},
		}
	}
	return dataForUserCert(cert)
}

func certificatesMatch(cert1, cert2 *pkicommon.UserCertificate) bool {
	if string(cert1.CA) != string(cert2.CA) || string(cert1.Certificate) != string(cert2.Certificate) || string(cert1.Key) != string(cert2.Key) {
		return false
	}
	return true
}

func dataForUserCert(cert *pkicommon.UserCertificate) map[string]interface{} {
	data := map[string]interface{}{
		corev1.TLSCertKey:       string(cert.Certificate),
		corev1.TLSPrivateKeyKey: string(cert.Key),
		v1alpha1.CoreCACertKey:  string(cert.CA),
	}
	if cert.JKS != nil && cert.Password != nil {
		data[v1alpha1.TLSJKSKey] = cert.JKS
		data[v1alpha1.PasswordKey] = string(cert.Password)
	}
	return data
}

func userCertForData(data map[string]interface{}) (*pkicommon.UserCertificate, error) {
	cert := &pkicommon.UserCertificate{}
	for _, key := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, v1alpha1.CoreCACertKey} {
		if _, ok := data[key]; !ok {
			return nil, fmt.Errorf("user secret does not contain required field: %s", key)
		}
	}
	certStr, _ := data[corev1.TLSCertKey].(string)
	keyStr, _ := data[corev1.TLSPrivateKeyKey].(string)
	caStr, _ := data[v1alpha1.CoreCACertKey].(string)

	cert.Certificate = []byte(certStr)
	cert.Key = []byte(keyStr)
	cert.CA = []byte(caStr)

	if _, ok := data[v1alpha1.TLSJKSKey]; ok {
		jks, _ := data[v1alpha1.TLSJKSKey].([]byte)
		cert.JKS = jks
	}

	if _, ok := data[v1alpha1.PasswordKey]; ok {
		passw, _ := data[v1alpha1.PasswordKey].(string)
		cert.Password = []byte(passw)
	}

	return cert, nil
}

func (v *vaultPKI) FinalizeUserCertificate(user *v1alpha1.KafkaUser) (err error) {
	client, err := v.getClient()
	if err != nil {
		return
	}

	certs, err := v.list(client, v.getUserStorePath())
	if err != nil {
		return
	}

	caCert, err := v.getCA(client)
	if err != nil {
		return
	}

	if !contains(certs, sanitizedResourceUid(user.GetUID())) {
		// we'll just assume we already cleaned up
		return nil
	}

	userSecret, err := client.Logical().Read(
		fmt.Sprintf("%s/%s", v.getUserStorePath(), sanitizedResourceUid(user.GetUID())),
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to retrieve user certificate")
	}

	userCert := rawToCertificate(userSecret.Data, caCert)

	// Revoke the certificate
	if _, err = client.Logical().Write(
		fmt.Sprintf("%s/revoke", v.getIntermediatePath()),
		map[string]interface{}{
			"serial_number": userCert.Serial,
		},
	); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to revoke user certificate")
	}

	// Delete entry from user store
	if _, err = client.Logical().Delete(
		fmt.Sprintf("%s/%s", v.getUserStorePath(), sanitizedResourceUid(user.GetUID())),
	); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to delete certificate from user store")
	}

	// Delete the user secret
	var storePath string
	storePath = user.Spec.SecretName

	mountPath, v2, err := isKVv2(storePath, client)
	if err != nil {
		return
	}

	if v2 {
		storePath = addPrefixToVKVPath(storePath, mountPath, "data")
	}

	if _, err = client.Logical().Delete(storePath); err != nil {
		err = errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to delete secret from user provided location")
	}

	return nil
}