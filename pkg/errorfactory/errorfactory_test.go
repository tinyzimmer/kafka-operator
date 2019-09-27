package errorfactory

import (
	"errors"
	"reflect"
	"testing"
)

var errorTypes = []error{
	ResourceNotReady{},
	APIFailure{},
	VaultAPIFailure{},
	StatusUpdateError{},
	BrokersUnreachable{},
	BrokersNotReady{},
	BrokersRequestError{},
	CreateTopicError{},
	TopicNotFound{},
	GracefulUpscaleFailed{},
	TooManyResources{},
	InternalError{},
	FatalReconcileError{},
}

func TestNew(t *testing.T) {
	for _, errType := range errorTypes {
		err := New(errType, errors.New("test-error"), "test-message")
		expected := "test-message: test-error"
		got := err.Error()
		if got != expected {
			t.Error("Expected:", expected, "got:", got)
		}
		if reflect.TypeOf(err) != reflect.TypeOf(errType) {
			t.Error("Expected:", reflect.TypeOf(errType), "got:", reflect.TypeOf(err))
		}
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("The code did not panic")
		}
	}()

	New(nil, errors.New("test"), "test")
}
