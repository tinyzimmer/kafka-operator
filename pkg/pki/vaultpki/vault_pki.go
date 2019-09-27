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
	"context"
	"fmt"
	"strings"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/pkg/certutil"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/resources/templates"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const pkiOU = "vault-pki"

func (v *vaultPKI) FinalizePKI(logger logr.Logger) error {
	vault, err := v.getClient()
	if err != nil {
		return err
	}

	// Make sure we finished cleaning up users - the controller should have
	// triggered a delete of all children for this cluster
	users, err := v.list(vault, v.getUserStorePath())
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "could not list user certificates")
	}
	for _, user := range users {
		if user != "broker" && user != "controller" {
			err = fmt.Errorf("Non broker/controller user exists: %s", user)
			return errorfactory.New(errorfactory.ResourceNotReady{}, err, "pki still contains user certificates")
		}
	}

	// List the currently mounted backends
	presentMounts, err := vault.Sys().ListMounts()
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "could not list system mounts in vault")
	}

	checkMounts := []string{
		fmt.Sprintf("%s/", v.getUserStorePath()),
		fmt.Sprintf("%s/", v.getIntermediatePath()),
		fmt.Sprintf("%s/", v.getCAPath()),
	}

	// Iterate our mounts and unmount if present
	for _, mount := range checkMounts {
		if _, ok := presentMounts[mount]; ok {
			logger.Info("Unmounting vault path", "mount", mount)
			if err := vault.Sys().Unmount(mount[:len(mount)-1]); err != nil {
				return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "could not unmount vault path", "path", mount)
			}
		}
	}

	return nil
}

func (v *vaultPKI) ReconcilePKI(logger logr.Logger, scheme *runtime.Scheme) (err error) {
	log := logger.WithName("vault_pki")

	vault, err := v.getClient()
	if err != nil {
		return
	}

	// List the currently mounted backends
	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "could not list system mounts in vault")
	}

	// For all method calls below, err has already been wrapped through the errorfactory

	// Assume that if our intermediate doesn't exist we need to do an initial setup
	// TODO: There might be a safer way to do this
	if _, ok := mounts[fmt.Sprintf("%s/", v.getIntermediatePath())]; !ok {
		log.Info("Creating new vault PKI", "vault_addr", vault.Address())
		if err = v.initVaultPKI(vault); err != nil {
			return
		}
	}

	caCert, err := v.getCA(vault)
	if err != nil {
		return
	}

	brokerCert, err := v.ensureBrokerCert(vault, caCert)
	if err != nil {
		return
	}

	controllerCert, err := v.ensureControllerCert(vault, caCert)
	if err != nil {
		return
	}

	return v.ensureBootstrapSecrets(scheme, brokerCert, controllerCert)
}

func (v *vaultPKI) ensureBootstrapSecrets(scheme *runtime.Scheme, brokerCert, controllerCert *pkicommon.UserCertificate) (err error) {
	bootstrapSecret := &corev1.Secret{}
	passwordSecret := &corev1.Secret{}

	toCreate := make([]*corev1.Secret, 0)

	if err = v.client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      v.cluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName,
			Namespace: v.cluster.Namespace,
		},
		bootstrapSecret,
	); err != nil {
		if apierrors.IsNotFound(err) {
			certs := &corev1.Secret{
				ObjectMeta: templates.ObjectMeta(v.cluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName, pkicommon.LabelsForKafkaPKI(v.cluster.Name), v.cluster),
				Data: map[string][]byte{
					v1alpha1.CACertKey:           brokerCert.CA,
					v1alpha1.PeerCertKey:         brokerCert.Certificate,
					v1alpha1.PeerPrivateKeyKey:   brokerCert.Key,
					v1alpha1.ClientCertKey:       controllerCert.Certificate,
					v1alpha1.ClientPrivateKeyKey: controllerCert.Key,
				},
			}
			controllerutil.SetControllerReference(v.cluster, certs, scheme)
			toCreate = append(toCreate, certs)
		} else {
			return errorfactory.New(errorfactory.APIFailure{}, err, "failed to check existence of bootstrap secret")
		}
	}

	if err = v.client.Get(
		context.TODO(),
		types.NamespacedName{
			Name:      v.cluster.Spec.ListenersConfig.SSLSecrets.JKSPasswordName,
			Namespace: v.cluster.Namespace,
		},
		passwordSecret,
	); err != nil {
		if apierrors.IsNotFound(err) {
			passw := &corev1.Secret{
				ObjectMeta: templates.ObjectMeta(v.cluster.Spec.ListenersConfig.SSLSecrets.JKSPasswordName, pkicommon.LabelsForKafkaPKI(v.cluster.Name), v.cluster),
				Data: map[string][]byte{
					v1alpha1.PasswordKey: certutil.GeneratePass(16),
				},
			}
			controllerutil.SetControllerReference(v.cluster, passw, scheme)
			toCreate = append(toCreate, passw)
		} else {
			return errorfactory.New(errorfactory.APIFailure{}, err, "failed to check existence of bootstrap password")
		}
	}

	for _, o := range toCreate {
		if err = v.client.Create(context.TODO(), o); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "failed to create bootstrap secret", "secret", o.Name)
		}
	}

	return
}

func (v *vaultPKI) ensureBrokerCert(vault *vaultapi.Client, caCert string) (brokerCert *pkicommon.UserCertificate, err error) {
	certs, err := v.list(vault, v.getUserStorePath())
	if err != nil {
		return
	}

	var user *vaultapi.Secret
	if contains(certs, "broker") {
		user, err = vault.Logical().Read(
			fmt.Sprintf("%s/broker", v.getUserStorePath()),
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to retrieve broker certificate")
		}
	} else {
		user, err = vault.Logical().Write(
			v.getIssuePath(),
			map[string]interface{}{
				vaultCommonNameArg:       pkicommon.GetCommonName(v.cluster),
				vaultAltNamesArg:         strings.Join(pkicommon.GetDNSNames(v.cluster), ","),
				vaultTTLArg:              "60000h",
				vaultPrivateKeyFormatArg: "pkcs8",
			},
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to create broker certificate")
		}
		_, err = vault.Logical().Write(
			fmt.Sprintf("%s/broker", v.getUserStorePath()),
			user.Data,
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to store broker certificate")
		}
	}

	brokerCert = rawToBootstrapCertificate(user.Data, caCert)

	return
}

func (v *vaultPKI) ensureControllerCert(vault *vaultapi.Client, caCert string) (controllerCert *pkicommon.UserCertificate, err error) {
	certs, err := v.list(vault, v.getUserStorePath())
	if err != nil {
		return
	}

	var user *vaultapi.Secret
	if contains(certs, "controller") {
		user, err = vault.Logical().Read(
			fmt.Sprintf("%s/controller", v.getUserStorePath()),
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to retrieve controller certificate")
		}
	} else {
		user, err = vault.Logical().Write(
			v.getIssuePath(),
			map[string]interface{}{
				vaultCommonNameArg:        fmt.Sprintf("%s-controller", v.cluster.Name),
				vaultTTLArg:               "60000h",
				vaultPrivateKeyFormatArg:  "pkcs8",
				vaultExcludeCNFromSANSArg: true,
			},
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to create controller certificate")
		}
		_, err = vault.Logical().Write(
			fmt.Sprintf("%s/controller", v.getUserStorePath()),
			user.Data,
		)
		if err != nil {
			return nil, errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to store controller certificate")
		}
	}

	controllerCert = rawToBootstrapCertificate(user.Data, caCert)

	return
}

func (v *vaultPKI) initVaultPKI(vault *vaultapi.Client) error {
	caPath := v.getCAPath()
	intermediatePath := v.getIntermediatePath()
	userPath := v.getUserStorePath()
	var err error

	// Setup a PKI mount for the ca
	if err = vault.Sys().Mount(
		caPath,
		&vaultapi.MountInput{
			Type: vaultBackendPKI,
			Config: vaultapi.MountConfigInput{
				MaxLeaseTTL: "219000h",
			},
		}); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to setup mount for root pki")
	}

	// Setup a PKI mount for the intermediate
	if err = vault.Sys().Mount(
		intermediatePath,
		&vaultapi.MountInput{
			Type: vaultBackendPKI,
			Config: vaultapi.MountConfigInput{
				MaxLeaseTTL: "219000h",
			},
		}); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to setup mount for intermediate pki")
	}

	// Setup a KV mount for user certificates
	if err = vault.Sys().Mount(
		userPath,
		&vaultapi.MountInput{
			Type: vaultBackendKV,
		},
	); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to setup kv mount for user certificate store")
	}

	// Create a root CA
	_, err = vault.Logical().Write(
		fmt.Sprintf("%s/root/generate/internal", caPath),
		map[string]interface{}{
			vaultCommonNameArg:        fmt.Sprintf(pkicommon.CAFQDNTemplate, v.cluster.Name, v.cluster.Namespace),
			vaultOUArg:                pkiOU,
			vaultExcludeCNFromSANSArg: true,
			vaultTTLArg:               "215000h",
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to generate root certificate")
	}

	// set information about distribution points and so on
	_, err = vault.Logical().Write(
		fmt.Sprintf("%s/config/urls", caPath),
		map[string]interface{}{
			vaultIssuingCertificates:   fmt.Sprintf("%s/v1/%s/ca", vault.Address(), caPath),
			vaultCRLDistributionPoints: fmt.Sprintf("%s/v1/%s/crl", vault.Address(), caPath),
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to write config for root pki")
	}

	// Create a CSR for an intermediate
	csr, err := vault.Logical().Write(
		fmt.Sprintf("%s/intermediate/generate/internal", intermediatePath),
		map[string]interface{}{
			vaultCommonNameArg:        fmt.Sprintf(pkicommon.CAIntermediateTemplate, v.cluster.Name, v.cluster.Namespace),
			vaultOUArg:                pkiOU,
			vaultExcludeCNFromSANSArg: true,
			vaultTTLArg:               "209999h",
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to create intermediate csr")
	}

	// Sign the intermediate CSR
	signedIntermediate, err := vault.Logical().Write(
		fmt.Sprintf("%s/root/sign-intermediate", caPath),
		map[string]interface{}{
			vaultCSRArg:       csr.Data["csr"],
			vaultCSRFormatArg: "pem_bundle",
			vaultTTLArg:       "209999h",
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to sign intermediate certificate")
	}

	// Write the signed intermediate back to the PKI
	_, err = vault.Logical().Write(
		fmt.Sprintf("%s/intermediate/set-signed", intermediatePath),
		map[string]interface{}{
			vaultCertificateKey: signedIntermediate.Data[vaultCertificateKey],
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to set signed certificate for intermediate pki")
	}

	// set information about distribution points and so on
	_, err = vault.Logical().Write(
		fmt.Sprintf("%s/config/urls", intermediatePath),
		map[string]interface{}{
			vaultIssuingCertificates:   fmt.Sprintf("%s/v1/%s/ca", vault.Address(), intermediatePath),
			vaultCRLDistributionPoints: fmt.Sprintf("%s/v1/%s/crl", vault.Address(), intermediatePath),
		},
	)
	if err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to write config for intermediate pki")
	}

	// Create a role that can issue certificates
	if _, err = vault.Logical().Write(
		fmt.Sprintf("%s/roles/operator", intermediatePath),
		map[string]interface{}{
			vaultAllowLocalhost:   true,
			vaultAllowedDomains:   "*",
			vaultAllowSubdomains:  true,
			vaultMaxTTL:           "60000h",
			vaultAllowAnyName:     true,
			vaultAllowIPSANS:      true,
			vaultAllowGlobDomains: true,
			vaultOrganization:     pkiOU,
			vaultUseCSRCommonName: false,
			vaultUseCSRSANS:       false,
		},
	); err != nil {
		return errorfactory.New(errorfactory.VaultAPIFailure{}, err, "failed to create issuer role for intermediate pki")
	}

	return nil
}
