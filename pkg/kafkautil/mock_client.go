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

package kafkautil

import (
	"errors"
	"time"

	"github.com/Shopify/sarama"
)

type MockClusterAdmin struct {
	sarama.ClusterAdmin

	failOps bool
}

func newMockClusterAdmin([]string, *sarama.Config) (sarama.ClusterAdmin, error) {
	return &MockClusterAdmin{}, nil
}

func newMockClusterAdminError([]string, *sarama.Config) (sarama.ClusterAdmin, error) {
	return &MockClusterAdmin{}, errors.New("bad client")
}

func newMockClusterAdminFailOps([]string, *sarama.Config) (sarama.ClusterAdmin, error) {
	return &MockClusterAdmin{failOps: true}, nil
}

func (m *MockClusterAdmin) Close() error { return nil }

func (m *MockClusterAdmin) DescribeCluster() ([]*sarama.Broker, int32, error) {
	if !m.failOps {
		return []*sarama.Broker{}, 0, nil
	}
	return []*sarama.Broker{}, 0, errors.New("bad describe cluster")
}

func (m *MockClusterAdmin) ListTopics() (map[string]sarama.TopicDetail, error) {
	if !m.failOps {
		return map[string]sarama.TopicDetail{
			"test-topic": sarama.TopicDetail{},
		}, nil
	}
	return map[string]sarama.TopicDetail{}, errors.New("bad list topics")
}

func (m *MockClusterAdmin) DescribeTopics(topics []string) ([]*sarama.TopicMetadata, error) {
	if !m.failOps {
		switch topics[0] {
		case "test-topic":
			return []*sarama.TopicMetadata{
				&sarama.TopicMetadata{
					Name:       "test-topic",
					Partitions: []*sarama.PartitionMetadata{&sarama.PartitionMetadata{}},
					Err:        sarama.ErrNoError,
				},
			}, nil
		case "not-exists":
			return []*sarama.TopicMetadata{}, nil
		case "with-error":
			return []*sarama.TopicMetadata{
				&sarama.TopicMetadata{
					Name:       "test-topic",
					Partitions: []*sarama.PartitionMetadata{&sarama.PartitionMetadata{}},
					Err:        sarama.ErrUnknown,
				},
			}, nil
		}
	}
	return []*sarama.TopicMetadata{}, errors.New("bad describe topics")
}

func (m *MockClusterAdmin) CreateTopic(name string, detail *sarama.TopicDetail, validateOnly bool) error {
	if !m.failOps {
		return nil
	}
	return errors.New("bad create topic")
}

func (m *MockClusterAdmin) DeleteTopic(name string) error {
	if !m.failOps {
		return nil
	}
	return errors.New("bad delete topic")
}

func (m *MockClusterAdmin) AlterConfig(resource sarama.ConfigResourceType, topic string, conf map[string]*string, validateOnly bool) error {
	if !m.failOps {
		return nil
	}
	return errors.New("bad alter config")
}

func (m *MockClusterAdmin) CreatePartitions(topic string, count int32, assn [][]int32, validateOnly bool) error {
	return nil
}

func (m *MockClusterAdmin) CreateACL(resource sarama.Resource, acl sarama.Acl) error {
	if !m.failOps {
		return nil
	}
	return errors.New("bad create acl")
}

func (m *MockClusterAdmin) DeleteACL(filter sarama.AclFilter, validateOnly bool) ([]sarama.MatchingAcl, error) {
	if !m.failOps {
		switch *filter.Principal {
		case "test-user":
			return []sarama.MatchingAcl{sarama.MatchingAcl{}}, nil
		case "with-error":
			return []sarama.MatchingAcl{sarama.MatchingAcl{Err: sarama.ErrUnknown}}, nil
		}
	}
	return []sarama.MatchingAcl{}, errors.New("bad create acl")
}

func newMockOpts() *KafkaConfig {
	return &KafkaConfig{
		OperationTimeout: kafkaDefaultTimeout,
		openOnNew:        false,
	}
}

func newMockClient() *kafkaClient {
	return &kafkaClient{
		opts:            newMockOpts(),
		timeout:         time.Duration(kafkaDefaultTimeout) * time.Second,
		newClusterAdmin: newMockClusterAdmin,
	}
}

func newOpenedMockClient() *kafkaClient {
	client := newMockClient()
	client.Open()
	return client
}
