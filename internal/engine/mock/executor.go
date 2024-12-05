// Code generated by MockGen. DO NOT EDIT.
// Source: ./executor.go
//
// Generated by this command:
//
//	mockgen -package mock_engine -destination=./mock/executor.go -source=./executor.go
//

// Package mock_engine is a generated GoMock package.
package mock_engine

import (
	context "context"
	reflect "reflect"

	entities "github.com/mindersec/minder/internal/engine/entities"
	gomock "go.uber.org/mock/gomock"
)

// MockExecutor is a mock of Executor interface.
type MockExecutor struct {
	ctrl     *gomock.Controller
	recorder *MockExecutorMockRecorder
	isgomock struct{}
}

// MockExecutorMockRecorder is the mock recorder for MockExecutor.
type MockExecutorMockRecorder struct {
	mock *MockExecutor
}

// NewMockExecutor creates a new mock instance.
func NewMockExecutor(ctrl *gomock.Controller) *MockExecutor {
	mock := &MockExecutor{ctrl: ctrl}
	mock.recorder = &MockExecutorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockExecutor) EXPECT() *MockExecutorMockRecorder {
	return m.recorder
}

// EvalEntityEvent mocks base method.
func (m *MockExecutor) EvalEntityEvent(ctx context.Context, inf *entities.EntityInfoWrapper) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EvalEntityEvent", ctx, inf)
	ret0, _ := ret[0].(error)
	return ret0
}

// EvalEntityEvent indicates an expected call of EvalEntityEvent.
func (mr *MockExecutorMockRecorder) EvalEntityEvent(ctx, inf any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EvalEntityEvent", reflect.TypeOf((*MockExecutor)(nil).EvalEntityEvent), ctx, inf)
}
