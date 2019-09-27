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

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/k8sutil"
	"github.com/banzaicloud/kafka-operator/pkg/kafkaclient"
	"github.com/banzaicloud/kafka-operator/pkg/pki"
	"github.com/banzaicloud/kafka-operator/pkg/util"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
	"github.com/go-logr/logr"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/controller-runtime/pkg/source"
)

var userFinalizer = "finalizer.kafkausers.kafka.banzaicloud.io"

// SetupKafkaUserWithManager registers KafkaUser controller to the manager
func SetupKafkaUserWithManager(mgr ctrl.Manager) error {
	// Create a new reconciler
	r := &KafkaUserReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("controllers").WithName("KafkaUser"),
	}

	// Create a new controller
	c, err := controller.New("kafkauser", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource KafkaUser
	err = c.Watch(&source.Kind{Type: &v1alpha1.KafkaUser{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to secondary certificates and requeue the owner KafkaUser
	// TODO (tinyzimmer): With supporting a second backend, we can reasonably allow the user to not
	// have cert-manager installed in the cluster - therefore we don't need to watch
	err = c.Watch(&source.Kind{Type: &certv1.Certificate{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.KafkaUser{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that KafkaUserReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &KafkaUserReconciler{}

// KafkaUserReconciler reconciles a KafkaUser object
type KafkaUserReconciler struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	Client client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=kafka.banzaicloud.io,resources=kafkausers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kafka.banzaicloud.io,resources=kafkausers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=issuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=clusterissuers,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads that state of the cluster for a KafkaUser object and makes changes based on the state read
// and what is in the KafkaUser.Spec
func (r *KafkaUserReconciler) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := r.Log.WithValues("kafkauser", request.NamespacedName, "Request.Name", request.Name)
	reqLogger.Info("Reconciling KafkaUser")
	var err error
	// Fetch the KafkaUser instance
	instance := &v1alpha1.KafkaUser{}
	if err = r.Client.Get(context.TODO(), request.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			return reconciled()
		}
		// Error reading the object - requeue the request.
		return requeueWithError(reqLogger, err.Error(), err)
	}

	// Get the referenced kafkacluster
	clusterNamespace := instance.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = instance.Namespace
	}
	var cluster *v1beta1.KafkaCluster
	if cluster, err = k8sutil.LookupKafkaCluster(r.Client, instance.Spec.ClusterRef.Name, clusterNamespace); err != nil {
		// This shouldn't trigger anymore, but leaving it here as a safetybelt
		if k8sutil.IsMarkedForDeletion(instance.ObjectMeta) {
			reqLogger.Info("Cluster is gone already, there is nothing we can do")
			if err = r.removeFinalizer(instance); err != nil {
				return requeueWithError(reqLogger, "failed to remove finalizer from kafkauser", err)
			}
			return reconciled()
		}
		return requeueWithError(reqLogger, "failed to lookup referenced cluster", err)
	}

	// Get a kafka connection
	reqLogger.Info("Retrieving kafka admin client")
	broker, err := kafkaclient.NewFromCluster(r.Client, cluster)
	if err != nil {
		switch err.(type) {
		case errorfactory.BrokersUnreachable:
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Duration(15) * time.Second,
			}, nil
		case errorfactory.BrokersNotReady:
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Duration(15) * time.Second,
			}, nil
		case errorfactory.ResourceNotReady:
			reqLogger.Info("Controller secret not found, may not be ready")
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Duration(5) * time.Second,
			}, nil
		default:
			return requeueWithError(reqLogger, err.Error(), err)
		}
	}
	defer func() {
		if err := broker.Close(); err != nil {
			reqLogger.Error(err, "could not close client")
		}
	}()

	pkiManager := pki.GetPKIManager(r.Client, cluster)

	// Reconcile no matter what to get a user certificate instance for ACL management
	// TODO (tinyzimmer): This can go wrong if the user made a mistake in their secret path
	// using the vault backend, then tried to delete and fix it. Should probably
	// have the PKIManager export a GetUserCertificate specifically for deletions
	// that will allow the error to fall through if the certificate doesn't exist.
	user, err := pkiManager.ReconcileUserCertificate(instance, r.Scheme)
	if err != nil {
		switch err.(type) {
		case errorfactory.ResourceNotReady:
			reqLogger.Info("generated secret not found, may not be ready")
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Duration(5) * time.Second,
			}, nil
		default:
			return requeueWithError(reqLogger, "failed to reconcile user secret", err)
		}
	}

	// check if marked for deletion
	if k8sutil.IsMarkedForDeletion(instance.ObjectMeta) {
		reqLogger.Info("Kafka user is marked for deletion, revoking certificates")
		if err = pkiManager.FinalizeUserCertificate(instance); err != nil {
			return requeueWithError(reqLogger, "failed to finalize user certificate", err)
		}
		return r.checkFinalizers(reqLogger, broker, instance, user)
	}

	// ensure ACLs - CreateUserACLs returns no error if the ACLs already exist
	// TODO (tinyzimmer): Should probably take this opportunity to see if we are removing any ACLs
	for _, grant := range instance.Spec.TopicGrants {
		reqLogger.Info(fmt.Sprintf("Ensuring %s ACLs for User: %s -> Topic: %s", grant.AccessType, user.DN(), grant.TopicName))
		if err = broker.CreateUserACLs(grant.AccessType, user.DN(), grant.TopicName); err != nil {
			return requeueWithError(reqLogger, "failed to ensure ACLs for kafkauser", err)
		}
	}

	// ensure a finalizer for cleanup on deletion
	if !util.StringSliceContains(instance.GetFinalizers(), userFinalizer) {
		r.addFinalizer(reqLogger, instance)
		if err = r.Client.Update(context.TODO(), instance); err != nil {
			return requeueWithError(reqLogger, "failed to update kafkauser with finalizer", err)
		}
	}

	return reconciled()
}

func (r *KafkaUserReconciler) checkFinalizers(reqLogger logr.Logger, broker kafkaclient.KafkaClient, instance *v1alpha1.KafkaUser, user *pkicommon.UserCertificate) (reconcile.Result, error) {
	// run finalizers
	var err error
	if util.StringSliceContains(instance.GetFinalizers(), userFinalizer) {
		if err = r.finalizeKafkaUser(reqLogger, broker, user); err != nil {
			return requeueWithError(reqLogger, "failed to finalize kafkauser", err)
		}
		// remove finalizer
		if err = r.removeFinalizer(instance); err != nil {
			return requeueWithError(reqLogger, "failed to remove finalizer from kafkauser", err)
		}
	}
	return reconciled()
}

func (r *KafkaUserReconciler) removeFinalizer(user *v1alpha1.KafkaUser) error {
	user.SetFinalizers(util.StringSliceRemove(user.GetFinalizers(), userFinalizer))
	return r.Client.Update(context.TODO(), user)
}

func (r *KafkaUserReconciler) finalizeKafkaUser(reqLogger logr.Logger, broker kafkaclient.KafkaClient, user *pkicommon.UserCertificate) error {
	var err error
	reqLogger.Info("Deleting user ACLs from kafka")
	if err = broker.DeleteUserACLs(user.DN()); err != nil {
		return err
	}
	return nil
}

func (r *KafkaUserReconciler) addFinalizer(reqLogger logr.Logger, user *v1alpha1.KafkaUser) {
	reqLogger.Info("Adding Finalizer for the KafkaUser")
	user.SetFinalizers(append(user.GetFinalizers(), userFinalizer))
	return
}
