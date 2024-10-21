// Code generated by MockGen. DO NOT EDIT.
// Source: ./service.go
//
// Generated by this command:
//
//	mockgen -package mock_history -destination=./mock/service.go -source=./service.go
//

// Package mock_history is a generated GoMock package.
package mock_history

import (
	context "context"
	reflect "reflect"

	uuid "github.com/google/uuid"
	db "github.com/mindersec/minder/internal/db"
	history "github.com/mindersec/minder/internal/history"
	gomock "go.uber.org/mock/gomock"
)

// MockEvaluationHistoryService is a mock of EvaluationHistoryService interface.
type MockEvaluationHistoryService struct {
	ctrl     *gomock.Controller
	recorder *MockEvaluationHistoryServiceMockRecorder
	isgomock struct{}
}

// MockEvaluationHistoryServiceMockRecorder is the mock recorder for MockEvaluationHistoryService.
type MockEvaluationHistoryServiceMockRecorder struct {
	mock *MockEvaluationHistoryService
}

// NewMockEvaluationHistoryService creates a new mock instance.
func NewMockEvaluationHistoryService(ctrl *gomock.Controller) *MockEvaluationHistoryService {
	mock := &MockEvaluationHistoryService{ctrl: ctrl}
	mock.recorder = &MockEvaluationHistoryServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEvaluationHistoryService) EXPECT() *MockEvaluationHistoryServiceMockRecorder {
	return m.recorder
}

// ListEvaluationHistory mocks base method.
func (m *MockEvaluationHistoryService) ListEvaluationHistory(ctx context.Context, qtx db.ExtendQuerier, cursor *history.ListEvaluationCursor, size uint32, filter history.ListEvaluationFilter) (*history.ListEvaluationHistoryResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEvaluationHistory", ctx, qtx, cursor, size, filter)
	ret0, _ := ret[0].(*history.ListEvaluationHistoryResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListEvaluationHistory indicates an expected call of ListEvaluationHistory.
func (mr *MockEvaluationHistoryServiceMockRecorder) ListEvaluationHistory(ctx, qtx, cursor, size, filter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEvaluationHistory", reflect.TypeOf((*MockEvaluationHistoryService)(nil).ListEvaluationHistory), ctx, qtx, cursor, size, filter)
}

// StoreEvaluationStatus mocks base method.
func (m *MockEvaluationHistoryService) StoreEvaluationStatus(ctx context.Context, qtx db.Querier, ruleID, profileID uuid.UUID, entityType db.Entities, entityID uuid.UUID, evalError error, marshaledCheckpoint []byte) (uuid.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreEvaluationStatus", ctx, qtx, ruleID, profileID, entityType, entityID, evalError, marshaledCheckpoint)
	ret0, _ := ret[0].(uuid.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StoreEvaluationStatus indicates an expected call of StoreEvaluationStatus.
func (mr *MockEvaluationHistoryServiceMockRecorder) StoreEvaluationStatus(ctx, qtx, ruleID, profileID, entityType, entityID, evalError, marshaledCheckpoint any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreEvaluationStatus", reflect.TypeOf((*MockEvaluationHistoryService)(nil).StoreEvaluationStatus), ctx, qtx, ruleID, profileID, entityType, entityID, evalError, marshaledCheckpoint)
}
