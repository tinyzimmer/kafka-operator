package pkicommon

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/pkg/certutil"
)

func TestDN(t *testing.T) {
	cert, _, expected, err := certutil.GenerateTestCert()
	if err != nil {
		t.Fatal("failed to generate certificate for testing:", err)
	}
	userCert := &UserCertificate{
		Certificate: cert,
	}
	dn := userCert.DN()
	if dn != expected {
		t.Error("Expected:", expected, "got:", dn)
	}
}

func TestGetCommonName(t *testing.T) {
	cluster := &v1alpha1.KafkaCluster{}
	cluster.Name = "test-cluster"
	cluster.Namespace = "test-namespace"

	cluster.Spec = v1alpha1.KafkaClusterSpec{HeadlessServiceEnabled: true}
	headlessCN := GetCommonName(cluster)
	expected := "test-cluster-headless.test-namespace.svc.cluster.local"
	if headlessCN != expected {
		t.Error("Expected:", expected, "Got:", headlessCN)
	}

	cluster.Spec = v1alpha1.KafkaClusterSpec{HeadlessServiceEnabled: false}
	allBrokerCN := GetCommonName(cluster)
	expected = "test-cluster-all-broker.test-namespace.svc.cluster.local"
	if allBrokerCN != expected {
		t.Error("Expected:", expected, "Got:", allBrokerCN)
	}
}

func TestLabelsForKafkaPKI(t *testing.T) {
	expected := map[string]string{
		"app":          "kafka",
		"kafka_issuer": fmt.Sprintf(BrokerIssuerTemplate, "test"),
	}
	got := LabelsForKafkaPKI("test")
	if !reflect.DeepEqual(got, expected) {
		t.Error("Expected:", expected, "got:", got)
	}
}

func TestGetDNSNames(t *testing.T) {
	cluster := &v1alpha1.KafkaCluster{}
	cluster.Name = "test-cluster"
	cluster.Namespace = "test-namespace"

	cluster.Spec = v1alpha1.KafkaClusterSpec{}
	cluster.Spec.BrokerConfigs = []v1alpha1.BrokerConfig{
		v1alpha1.BrokerConfig{Id: 0},
	}

	cluster.Spec.HeadlessServiceEnabled = true
	headlessNames := GetDNSNames(cluster)
	expected := []string{
		"test-cluster-0.test-cluster-headless.test-namespace.svc.cluster.local",
		"test-cluster-0.test-cluster-headless.test-namespace.svc",
		"test-cluster-0.test-cluster-headless.test-namespace",
		"test-cluster-headless.test-namespace.svc.cluster.local",
		"test-cluster-headless.test-namespace.svc",
		"test-cluster-headless.test-namespace",
		"test-cluster-headless",
	}
	if !reflect.DeepEqual(expected, headlessNames) {
		t.Error("Expected:", expected, "got:", headlessNames)
	}

	cluster.Spec.HeadlessServiceEnabled = false
	allBrokerNames := GetDNSNames(cluster)
	expected = []string{
		"test-cluster-0.test-namespace.svc.cluster.local",
		"test-cluster-0.test-namespace.svc",
		"test-cluster-0.test-namespace",
		"test-cluster-all-broker.test-namespace.svc.cluster.local",
		"test-cluster-all-broker.test-namespace.svc",
		"test-cluster-all-broker.test-namespace",
		"test-cluster-all-broker",
	}
	if !reflect.DeepEqual(expected, allBrokerNames) {
		t.Error("Expected:", expected, "got:", allBrokerNames)
	}
}