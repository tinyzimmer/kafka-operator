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
	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/banzaicloud/kafka-operator/pkg/kafkaclient"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func requeueWithError(logger logr.Logger, msg string, err error) (ctrl.Result, error) {
	// Info log the error message and then let the reconciler dump the stacktrace
	logger.Info(msg)
	return ctrl.Result{}, err
}

func reconciled() (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func getClusterRefNamespace(ns string, ref v1alpha1.ClusterReference) string {
	clusterNamespace := ref.Namespace
	if clusterNamespace == "" {
		return ns
	}
	return clusterNamespace
}

func newBrokerConnection(log logr.Logger, client client.Client, cluster *v1beta1.KafkaCluster) (broker kafkaclient.KafkaClient, close func(), err error) {

	// Get a kafka connection
	log.Info("Retrieving kafka client")
	broker, err = kafkaclient.NewFromCluster(client, cluster)
	if err != nil {
		return
	}
	close = func() {
		if err := broker.Close(); err != nil {
			log.Error(err, "Error closing kafka client")
		}
	}
	return
}
