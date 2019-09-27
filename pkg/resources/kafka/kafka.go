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

package kafka

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	v1beta "github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/banzaicloud/kafka-operator/pkg/certutil"
	"github.com/banzaicloud/kafka-operator/pkg/errorfactory"
	"github.com/banzaicloud/kafka-operator/pkg/k8sutil"
	"github.com/banzaicloud/kafka-operator/pkg/kafkaclient"
	"github.com/banzaicloud/kafka-operator/pkg/resources"
	"github.com/banzaicloud/kafka-operator/pkg/resources/templates"
	"github.com/banzaicloud/kafka-operator/pkg/scale"
	"github.com/banzaicloud/kafka-operator/pkg/util"
	envoyutils "github.com/banzaicloud/kafka-operator/pkg/util/envoy"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	componentName         = "kafka"
	brokerConfigTemplate  = "%s-config"
	brokerStorageTemplate = "%s-storage"

	brokerConfigMapVolumeMount    = "broker-config"
	modbrokerConfigMapVolumeMount = "broker-modconfig"
	kafkaDataVolumeMount          = "kafka-data"
	keystoreVolume                = "ks-files"
	keystoreVolumePath            = "/var/run/secrets/java.io/keystores"
	pemFilesVolume                = "pem-files"
	jmxVolumePath                 = "/opt/jmx-exporter/"
	jmxVolumeName                 = "jmx-jar-data"
	metricsPort                   = 9020
)

// Reconciler implements the Component Reconciler
type Reconciler struct {
	resources.Reconciler
}

// labelsForKafka returns the labels for selecting the resources
// belonging to the given kafka CR name.
func labelsForKafka(name string) map[string]string {
	return map[string]string{"app": "kafka", "kafka_cr": name}
}

// New creates a new reconciler for Kafka
func New(client client.Client, cluster *v1beta1.KafkaCluster) *Reconciler {
	return &Reconciler{
		Reconciler: resources.Reconciler{
			Client:       client,
			KafkaCluster: cluster,
		},
	}
}

func getCreatedPVCForBroker(c client.Client, brokerID int32, namespace, crName string) ([]corev1.PersistentVolumeClaim, error) {
	foundPVCList := &corev1.PersistentVolumeClaimList{}
	matchingLabels := client.MatchingLabels{
		"kafka_cr": crName,
		"brokerId": fmt.Sprintf("%d", brokerID),
	}
	err := c.List(context.TODO(), foundPVCList, client.ListOption(client.InNamespace(namespace)), client.ListOption(matchingLabels))
	if err != nil {
		return nil, err
	}
	if len(foundPVCList.Items) == 0 {
		return nil, fmt.Errorf("no persistentvolume found for broker %d", brokerID)
	}
	return foundPVCList.Items, nil
}

func getLoadBalancerIP(client client.Client, namespace string, log logr.Logger) (string, error) {
	foundLBService := &corev1.Service{}
	err := client.Get(context.TODO(), types.NamespacedName{Name: envoyutils.EnvoyServiceName, Namespace: namespace}, foundLBService)
	if err != nil {
		return "", err
	}

	if len(foundLBService.Status.LoadBalancer.Ingress) == 0 {
		return "", errorfactory.New(errorfactory.ResourceNotReady{}, errors.New("loadbalancer is not created waiting"), "trying")
	}

	if foundLBService.Status.LoadBalancer.Ingress[0].Hostname == "" && foundLBService.Status.LoadBalancer.Ingress[0].IP == "" {
		time.Sleep(20 * time.Second)
		return "", errorfactory.New(errorfactory.ResourceNotReady{}, errors.New("loadbalancer is not created waiting"), "trying")
	}
	var loadBalancerExternalAddress string
	if foundLBService.Status.LoadBalancer.Ingress[0].Hostname == "" {
		loadBalancerExternalAddress = foundLBService.Status.LoadBalancer.Ingress[0].IP
	} else {
		loadBalancerExternalAddress = foundLBService.Status.LoadBalancer.Ingress[0].Hostname
	}
	return loadBalancerExternalAddress, nil
}

// Reconcile implements the reconcile logic for Kafka
func (r *Reconciler) Reconcile(log logr.Logger) error {
	log = log.WithValues("component", componentName)

	log.V(1).Info("Reconciling")

	if r.KafkaCluster.Spec.HeadlessServiceEnabled {
		o := r.headlessService()
		err := k8sutil.Reconcile(log, r.Client, o, r.KafkaCluster)
		if err != nil {
			return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
		}
	} else {
		o := r.allBrokerService()
		err := k8sutil.Reconcile(log, r.Client, o, r.KafkaCluster)
		if err != nil {
			return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
		}
	}
	// Handle Pod delete
	podList := &corev1.PodList{}
	matchingLabels := client.MatchingLabels{
		"kafka_cr": r.KafkaCluster.Name,
	}

	err := r.Client.List(context.TODO(), podList, client.ListOption(client.InNamespace(r.KafkaCluster.Namespace)), client.ListOption(matchingLabels))
	if err != nil {
		return errors.WrapIf(err, "failed to reconcile resource")
	}
	if len(podList.Items) > len(r.KafkaCluster.Spec.Brokers) {
		deletedBrokers := make([]corev1.Pod, 0)
	OUTERLOOP:
		for _, pod := range podList.Items {
			for _, broker := range r.KafkaCluster.Spec.Brokers {
				if pod.Labels["brokerId"] == fmt.Sprintf("%d", broker.Id) {
					continue OUTERLOOP
				}
			}
			deletedBrokers = append(deletedBrokers, pod)
		}
		for _, broker := range deletedBrokers {
			err = scale.DownsizeCluster(broker.Labels["brokerId"], broker.Namespace, r.KafkaCluster.Spec.CruiseControlConfig.CruiseControlEndpoint, r.KafkaCluster.Name)
			if err != nil {
				log.Error(err, "graceful downscale failed.")
			}
			err = r.Client.Delete(context.TODO(), &broker)
			if err != nil {
				return errors.WrapIfWithDetails(err, "could not delete broker", "id", broker.Labels["brokerId"])
			}
			err = r.Client.Delete(context.TODO(), &corev1.ConfigMap{ObjectMeta: templates.ObjectMeta(fmt.Sprintf(brokerConfigTemplate+"-%s", r.KafkaCluster.Name, broker.Labels["brokerId"]), labelsForKafka(r.KafkaCluster.Name), r.KafkaCluster)})
			if err != nil {
				return errors.WrapIfWithDetails(err, "could not delete configmap for broker", "id", broker.Labels["brokerId"])
			}
			if !r.KafkaCluster.Spec.HeadlessServiceEnabled {
				err = r.Client.Delete(context.TODO(), &corev1.Service{ObjectMeta: templates.ObjectMeta(fmt.Sprintf("%s-%s", r.KafkaCluster.Name, broker.Labels["brokerId"]), labelsForKafka(r.KafkaCluster.Name), r.KafkaCluster)})
				if err != nil {
					return errors.WrapIfWithDetails(err, "could not delete service for broker", "id", broker.Labels["brokerId"])
				}
			}
			for _, volume := range broker.Spec.Volumes {
				if strings.HasPrefix(volume.Name, kafkaDataVolumeMount) {
					err = r.Client.Delete(context.TODO(), &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
						Name:      volume.PersistentVolumeClaim.ClaimName,
						Namespace: r.KafkaCluster.Namespace,
					}})
					if err != nil {
						return errors.WrapIfWithDetails(err, "could not delete pvc for broker", "id", broker.Labels["brokerId"])
					}
				}
			}
			err = k8sutil.DeleteStatus(r.Client, broker.Labels["brokerId"], r.KafkaCluster, log)
			if err != nil {
				return errors.WrapIfWithDetails(err, "could not delete status for broker", "id", broker.Labels["brokerId"])
			}
		}
	}
	lBIp := ""

	if r.KafkaCluster.Spec.ListenersConfig.ExternalListeners != nil {
		lBIp, err = getLoadBalancerIP(r.Client, r.KafkaCluster.Namespace, log)
		if err != nil {
			return err
		}
	}
	//TODO remove after testing
	//lBIp := "192.168.0.1"

	// We need to grab names for servers and client in case user is enabling ACLs
	// That way we can continue to manage topics and users
	superUsers := make([]string, 0)
	if r.KafkaCluster.Spec.ListenersConfig.SSLSecrets != nil {
		controllerSecret := &corev1.Secret{}
		err = r.Client.Get(context.TODO(), types.NamespacedName{
			Name:      r.KafkaCluster.Spec.ListenersConfig.SSLSecrets.TLSSecretName,
			Namespace: r.KafkaCluster.Namespace,
		}, controllerSecret)
		if err != nil {
			return errors.WrapIfWithDetails(err, "failed to get controller secret, maybe still creating...")
		}
		for _, key := range []string{v1alpha1.ClientCertKey, v1alpha1.PeerCertKey} {
			su, err := certutil.DecodeCertificate(controllerSecret.Data[key])
			if err != nil {
				return errors.WrapIfWithDetails(err, "Failed to decode our client certificate")
			}
			superUsers = append(superUsers, su.Subject.String())
		}
	}

	for _, broker := range r.KafkaCluster.Spec.Brokers {
		brokerConfig, err := util.GetBrokerConfig(broker, r.KafkaCluster.Spec)
		if err != nil {
			return errors.WrapIf(err, "failed to reconcile resource")
		}
		for _, storage := range brokerConfig.StorageConfigs {
			o := r.pvc(broker.Id, storage, log)
			err := r.reconcileKafkaPVC(log, o.(*corev1.PersistentVolumeClaim))
			if err != nil {
				return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
			}

		}
		if r.KafkaCluster.Spec.RackAwareness == nil {
			o := r.configMap(broker.Id, brokerConfig, lBIp, superUsers, log)
			err := k8sutil.Reconcile(log, r.Client, o, r.KafkaCluster)
			if err != nil {
				return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
			}
		} else {
			if brokerState, ok := r.KafkaCluster.Status.BrokersState[strconv.Itoa(int(broker.Id))]; ok {
				if brokerState.RackAwarenessState == v1beta.Configured {
					o := r.configMap(broker.Id, brokerConfig, lBIp, superUsers, log)
					err := k8sutil.Reconcile(log, r.Client, o, r.KafkaCluster)
					if err != nil {
						return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
					}
				}
			}
		}

		pvcs, err := getCreatedPVCForBroker(r.Client, broker.Id, r.KafkaCluster.Namespace, r.KafkaCluster.Name)
		if err != nil {
			return errors.WrapIfWithDetails(err, "failed to list PVC's")
		}

		if !r.KafkaCluster.Spec.HeadlessServiceEnabled {
			o := r.service(broker.Id, log)
			err := k8sutil.Reconcile(log, r.Client, o, r.KafkaCluster)
			if err != nil {
				return errors.WrapIfWithDetails(err, "failed to reconcile resource", "resource", o.GetObjectKind().GroupVersionKind())
			}
		}
		o := r.pod(broker.Id, brokerConfig, pvcs, log)
		err = r.reconcileKafkaPod(log, o.(*corev1.Pod))
		if err != nil {
			return err
		}
		if err = r.reconcilePerBrokerDynamicConfig(broker.Id, brokerConfig, log); err != nil {
			return err
		}
	}

	if err = r.reconcileClusterWideDynamicConfig(log); err != nil {
		return err
	}

	log.V(1).Info("Reconciled")

	return nil
}

func (r *Reconciler) reconcilePerBrokerDynamicConfig(brokerId int32, brokerConfig *v1beta1.BrokerConfig, log logr.Logger) error {
	kClient, err := kafkaclient.NewFromCluster(r.Client, r.KafkaCluster)
	if err != nil {
		return errorfactory.New(errorfactory.BrokersUnreachable{}, err, "could not connect to kafka brokers")
	}
	defer func() {
		if err := kClient.Close(); err != nil {
			log.Error(err, "could not close client")
		}
	}()

	parsedBrokerConfig := util.ParsePropertiesFormat(brokerConfig.Config)

	// Calling DescribePerBrokerConfig with empty slice will return all config for that broker including the default ones
	if len(parsedBrokerConfig) > 0 {

		brokerConfigKeys := []string{}
		for key := range parsedBrokerConfig {
			brokerConfigKeys = append(brokerConfigKeys, key)
		}
		configIdentical := true

		response, err := kClient.DescribePerBrokerConfig(brokerId, brokerConfigKeys)
		if err != nil {
			return errors.WrapIfWithDetails(err, "could not describe broker config", "brokerId", brokerId)
		}

		if len(response) == 0 {
			configIdentical = false
		}
		for _, conf := range response {
			if val, ok := parsedBrokerConfig[conf.Name]; ok {
				if val != conf.Value {
					configIdentical = false
					break
				}
			}
		}
		if !configIdentical {
			err := kClient.AlterPerBrokerConfig(brokerId, util.ConvertMapStringToMapStringPointer(parsedBrokerConfig))
			if err != nil {
				return errors.WrapIfWithDetails(err, "could not alter broker config", "brokerId", brokerId)
			}
		}
	}
	return nil
}

func (r *Reconciler) reconcileClusterWideDynamicConfig(log logr.Logger) error {
	kClient, err := kafkaclient.NewFromCluster(r.Client, r.KafkaCluster)
	if err != nil {
		return errorfactory.New(errorfactory.BrokersUnreachable{}, err, "could not connect to kafka brokers")
	}
	defer func() {
		if err := kClient.Close(); err != nil {
			log.Error(err, "could not close client")
		}
	}()

	configIdentical := true

	currentConfig, err := kClient.DescribeClusterWideConfig()
	if err != nil {
		return errors.WrapIf(err, "could not describe cluster wide broker config")
	}
	parsedClusterWideConfig := util.ParsePropertiesFormat(r.KafkaCluster.Spec.ClusterWideConfig)
	if len(currentConfig) != len(parsedClusterWideConfig) {
		configIdentical = false
	}
	for _, conf := range currentConfig {
		if val, ok := parsedClusterWideConfig[conf.Name]; ok {
			if val != conf.Value {
				configIdentical = false
				break
			}
		}
	}
	if !configIdentical {
		err = kClient.AlterClusterWideConfig(util.ConvertMapStringToMapStringPointer(parsedClusterWideConfig))
		if err != nil {
			return errors.WrapIf(err, "could not alter cluster wide broker config")
		}
	}

	return nil
}

func (r *Reconciler) reconcileKafkaPod(log logr.Logger, desiredPod *corev1.Pod) error {
	currentPod := desiredPod.DeepCopy()
	desiredType := reflect.TypeOf(desiredPod)

	log = log.WithValues("kind", desiredType)
	log.V(1).Info("searching with label because name is empty")

	podList := &corev1.PodList{}
	matchingLabels := client.MatchingLabels{
		"kafka_cr": r.KafkaCluster.Name,
		"brokerId": desiredPod.Labels["brokerId"],
	}
	err := r.Client.List(context.TODO(), podList, client.InNamespace(currentPod.Namespace), matchingLabels)
	if err != nil && len(podList.Items) == 0 {
		return errorfactory.New(errorfactory.APIFailure{}, err, "getting resource failed", "kind", desiredType)
	}
	if len(podList.Items) == 0 {
		if err := patch.DefaultAnnotator.SetLastAppliedAnnotation(desiredPod); err != nil {
			return errors.WrapIf(err, "could not apply last state to annotation")
		}
		if err := r.Client.Create(context.TODO(), desiredPod); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "creating resource failed", "kind", desiredType)
		}
		// Update status to Config InSync because broker is configured to go
		statusErr := k8sutil.UpdateBrokerStatus(r.Client, desiredPod.Labels["brokerId"], r.KafkaCluster, v1beta.ConfigInSync, log)
		if statusErr != nil {
			return errorfactory.New(errorfactory.StatusUpdateError{}, err, "updating status for resource failed", "kind", desiredType)
		}
		if val, ok := r.KafkaCluster.Status.BrokersState[desiredPod.Labels["brokerId"]]; ok && val.GracefulActionState.CruiseControlState != v1beta.GracefulUpdateNotRequired {
			gracefulActionState := v1beta.GracefulActionState{ErrorMessage: "", CruiseControlState: v1beta.GracefulUpdateNotRequired}

			if r.KafkaCluster.Status.CruiseControlTopicStatus == v1beta.CruiseControlTopicReady {
				gracefulActionState = v1beta.GracefulActionState{ErrorMessage: "", CruiseControlState: v1beta.GracefulUpdateRequired}
			}
			statusErr = k8sutil.UpdateBrokerStatus(r.Client, desiredPod.Labels["brokerId"], r.KafkaCluster, gracefulActionState, log)
			if statusErr != nil {
				return errorfactory.New(errorfactory.StatusUpdateError{}, err, "could not update broker graceful action state")
			}
		}
		if r.KafkaCluster.Spec.RackAwareness != nil {
			if val, ok := r.KafkaCluster.Status.BrokersState[desiredPod.Labels["brokerId"]]; ok && val.RackAwarenessState == v1beta.Configured {
				return nil
			}
			statusErr := k8sutil.UpdateBrokerStatus(r.Client, desiredPod.Labels["brokerId"], r.KafkaCluster, v1beta.WaitingForRackAwareness, log)
			if statusErr != nil {
				return errorfactory.New(errorfactory.StatusUpdateError{}, err, "could not update broker rack state")
			}
		}

		log.Info("resource created")
		return nil
	} else if len(podList.Items) == 1 {
		currentPod = podList.Items[0].DeepCopy()
		brokerId := currentPod.Labels["brokerId"]
		if brokerState, ok := r.KafkaCluster.Status.BrokersState[brokerId]; ok {
			if r.KafkaCluster.Spec.RackAwareness != nil && (brokerState.RackAwarenessState == v1beta.WaitingForRackAwareness || brokerState.RackAwarenessState == "") {
				err := k8sutil.UpdateCrWithRackAwarenessConfig(currentPod, r.KafkaCluster, r.Client)
				if err != nil {
					return err
				}
				statusErr := k8sutil.UpdateBrokerStatus(r.Client, brokerId, r.KafkaCluster, v1beta.Configured, log)
				if statusErr != nil {
					return errorfactory.New(errorfactory.StatusUpdateError{}, err, "updating status for resource failed", "kind", desiredType)
				}
			}
			if currentPod.Status.Phase == corev1.PodRunning && brokerState.GracefulActionState.CruiseControlState == v1beta.GracefulUpdateRequired {
				scaleErr := scale.UpScaleCluster(desiredPod.Labels["brokerId"], desiredPod.Namespace, r.KafkaCluster.Spec.CruiseControlConfig.CruiseControlEndpoint, r.KafkaCluster.Name)
				if scaleErr != nil {
					log.Error(err, "graceful upscale failed, or cluster just started")
					statusErr := k8sutil.UpdateBrokerStatus(r.Client, brokerId, r.KafkaCluster,
						v1beta.GracefulActionState{ErrorMessage: scaleErr.Error(), CruiseControlState: v1beta.GracefulUpdateFailed}, log)
					if statusErr != nil {
						return errorfactory.New(errorfactory.StatusUpdateError{}, err, "could not update broker graceful action state")
					}
				} else {
					statusErr := k8sutil.UpdateBrokerStatus(r.Client, brokerId, r.KafkaCluster,
						v1beta.GracefulActionState{ErrorMessage: "", CruiseControlState: v1beta.GracefulUpdateSucceeded}, log)
					if statusErr != nil {
						return errorfactory.New(errorfactory.StatusUpdateError{}, err, "could not update broker graceful action state")
					}
				}
			}
		} else {
			return errorfactory.New(errorfactory.InternalError{}, errors.New("reconcile failed"), fmt.Sprintf("could not find status for the given broker id, %s", brokerId))
		}
	} else {
		return errorfactory.New(errorfactory.TooManyResources{}, errors.New("reconcile failed"), "more then one matching pod found", "labels", matchingLabels)
	}
	// TODO check if this err == nil check necessary (baluchicken)
	if err == nil {
		// Check if the resource actually updated
		patchResult, err := patch.DefaultPatchMaker.Calculate(currentPod, desiredPod)
		if err != nil {
			log.Error(err, "could not match objects", "kind", desiredType)
		} else if patchResult.IsEmpty() {
			if currentPod.Status.Phase != corev1.PodFailed && r.KafkaCluster.Status.BrokersState[currentPod.Labels["brokerId"]].ConfigurationState == v1beta.ConfigInSync {
				log.V(1).Info("resource is in sync")
				return nil
			}
		} else {
			log.V(1).Info("resource diffs",
				"patch", string(patchResult.Patch),
				"current", string(patchResult.Current),
				"modified", string(patchResult.Modified),
				"original", string(patchResult.Original))
		}

		if err := patch.DefaultAnnotator.SetLastAppliedAnnotation(desiredPod); err != nil {
			return errors.WrapIf(err, "could not apply last state to annotation")
		}

		if currentPod.Status.Phase != corev1.PodFailed {

			if r.KafkaCluster.Status.State != v1beta.KafkaClusterRollingUpgrading {
				if err := k8sutil.UpdateCRStatus(r.Client, r.KafkaCluster, v1beta.KafkaClusterRollingUpgrading, log); err != nil {
					return errorfactory.New(errorfactory.StatusUpdateError{}, err, "setting state to rolling upgrade failed")
				}
			}

			if r.KafkaCluster.Status.State == v1beta.KafkaClusterRollingUpgrading {
				// Check if any kafka pod is in terminating state
				podList := &corev1.PodList{}
				matchingLabels := client.MatchingLabels{
					"kafka_cr": r.KafkaCluster.Name,
					"app":      "kafka",
				}
				err := r.Client.List(context.TODO(), podList, client.ListOption(client.InNamespace(r.KafkaCluster.Namespace)), client.ListOption(matchingLabels))
				if err != nil {
					return errors.WrapIf(err, "failed to reconcile resource")
				}
				for _, pod := range podList.Items {
					if k8sutil.IsMarkedForDeletion(pod.ObjectMeta) {
						return errorfactory.New(errorfactory.ReconcileRollingUpgrade{}, errors.New("pod is still terminating"), "rolling upgrade in progress")
					}
				}
				errorCount := r.KafkaCluster.Status.RollingUpgrade.ErrorCount

				kClient, err := kafkaclient.NewFromCluster(r.Client, r.KafkaCluster)
				if err != nil {
					return errorfactory.New(errorfactory.BrokersUnreachable{}, err, "could not connect to kafka brokers")
				}
				defer func() {
					if err := kClient.Close(); err != nil {
						log.Error(err, "could not close client")
					}
				}()
				offlineReplicaCount, err := kClient.OfflineReplicaCount()
				if err != nil {
					return errors.WrapIf(err, "health check failed")
				}
				replicasInSync, err := kClient.AllReplicaInSync()
				if err != nil {
					return errors.WrapIf(err, "health check failed")
				}

				if offlineReplicaCount > 0 && !replicasInSync {
					errorCount++
				}
				if errorCount >= r.KafkaCluster.Spec.RollingUpgradeConfig.FailureThreshold {
					return errorfactory.New(errorfactory.ReconcileRollingUpgrade{}, errors.New("cluster is not healthy"), "rolling upgrade in progress")
				}
			}
		}

		err = k8sutil.UpdateCrWithNodeAffinity(currentPod, r.KafkaCluster, r.Client)
		if err != nil {
			return errorfactory.New(errorfactory.StatusUpdateError{}, err, "updating cr with node affinity failed")
		}
		err = r.Client.Delete(context.TODO(), currentPod)
		if err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "deleting resource failed", "kind", desiredType)
		}
	}
	return nil

}

func (r *Reconciler) reconcileKafkaPVC(log logr.Logger, desiredPVC *corev1.PersistentVolumeClaim) error {
	var currentPVC = desiredPVC.DeepCopy()
	desiredType := reflect.TypeOf(desiredPVC)
	log = log.WithValues("kind", desiredType)
	log.V(1).Info("searching with label because name is empty")

	pvcList := &corev1.PersistentVolumeClaimList{}
	matchingLabels := client.MatchingLabels{
		"kafka_cr": r.KafkaCluster.Name,
		"brokerId": desiredPVC.Labels["brokerId"],
	}
	err := r.Client.List(context.TODO(), pvcList,
		client.InNamespace(currentPVC.Namespace), matchingLabels)
	if err != nil && len(pvcList.Items) == 0 {
		return errorfactory.New(errorfactory.APIFailure{}, err, "getting resource failed", "kind", desiredType)
	}
	mountPath := currentPVC.Annotations["mountPath"]

	// Creating the first PersistentVolume For Pod
	if len(pvcList.Items) == 0 {
		if err := patch.DefaultAnnotator.SetLastAppliedAnnotation(desiredPVC); err != nil {
			return errors.WrapIf(err, "could not apply last state to annotation")
		}
		if err := r.Client.Create(context.TODO(), desiredPVC); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "creating resource failed", "kind", desiredType)
		}
		log.Info("resource created")
		return nil
	}
	alreadyCreated := false
	for _, pvc := range pvcList.Items {
		if mountPath == pvc.Annotations["mountPath"] {
			currentPVC = pvc.DeepCopy()
			alreadyCreated = true
			break
		}
	}
	if !alreadyCreated {
		// Creating the 2+ PersistentVolumes for Pod
		if err := patch.DefaultAnnotator.SetLastAppliedAnnotation(desiredPVC); err != nil {
			return errors.WrapIf(err, "could not apply last state to annotation")
		}
		if err := r.Client.Create(context.TODO(), desiredPVC); err != nil {
			return errorfactory.New(errorfactory.APIFailure{}, err, "creating resource failed", "kind", desiredType)
		}
		return nil
	}
	if err == nil {
		if k8sutil.CheckIfObjectUpdated(log, desiredType, currentPVC, desiredPVC) {

			if err := patch.DefaultAnnotator.SetLastAppliedAnnotation(desiredPVC); err != nil {
				return errors.WrapIf(err, "could not apply last state to annotation")
			}
			desiredPVC = currentPVC

			if err := r.Client.Update(context.TODO(), desiredPVC); err != nil {
				return errorfactory.New(errorfactory.APIFailure{}, err, "updating resource failed", "kind", desiredType)
			}
			log.Info("resource updated")
		}
	}
	return nil
}
