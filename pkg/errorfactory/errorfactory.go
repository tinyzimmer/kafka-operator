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

package errorfactory

import "emperror.dev/emperror"

type ResourceNotReady struct{ error }
type APIFailure struct{ error }
type VaultAPIFailure struct{ error }
type StatusUpdateError struct{ error }
type BrokersUnreachable struct{ error }
type BrokersNotReady struct{ error }
type BrokersRequestError struct{ error }
type CreateTopicError struct{ error }
type TopicNotFound struct{ error }
type GracefulUpscaleFailed struct{ error }
type TooManyResources struct{ error }
type InternalError struct{ error }
type FatalReconcileError struct{ error }

func New(t interface{}, err error, msg string, wrapArgs ...interface{}) error {
	wrapped := emperror.WrapWith(err, msg, wrapArgs)
	switch t.(type) {
	case ResourceNotReady:
		return ResourceNotReady{wrapped}
	case APIFailure:
		return APIFailure{wrapped}
	case VaultAPIFailure:
		return VaultAPIFailure{wrapped}
	case StatusUpdateError:
		return StatusUpdateError{wrapped}
	case BrokersUnreachable:
		return BrokersUnreachable{wrapped}
	case BrokersNotReady:
		return BrokersNotReady{wrapped}
	case BrokersRequestError:
		return BrokersRequestError{wrapped}
	case GracefulUpscaleFailed:
		return GracefulUpscaleFailed{wrapped}
	case TopicNotFound:
		return TopicNotFound{wrapped}
	case CreateTopicError:
		return CreateTopicError{wrapped}
	case TooManyResources:
		return TooManyResources{wrapped}
	case InternalError:
		return InternalError{wrapped}
	case FatalReconcileError:
		return FatalReconcileError{wrapped}
	}
	panic("Invalid error type")
}
