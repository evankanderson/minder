// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/mindpak/reader/reader.go
//
// Generated by this command:
//
//	mockgen -package mockbundle -destination internal/marketplaces/bundles/mock/reader.go -source pkg/mindpak/reader/reader.go
//

// Package mockbundle is a generated GoMock package.
package mockbundle

import (
	reflect "reflect"

	v1 "github.com/mindersec/minder/pkg/api/protobuf/go/minder/v1"
	mindpak "github.com/mindersec/minder/pkg/mindpak"
	gomock "go.uber.org/mock/gomock"
)

// MockBundleReader is a mock of BundleReader interface.
type MockBundleReader struct {
	ctrl     *gomock.Controller
	recorder *MockBundleReaderMockRecorder
	isgomock struct{}
}

// MockBundleReaderMockRecorder is the mock recorder for MockBundleReader.
type MockBundleReaderMockRecorder struct {
	mock *MockBundleReader
}

// NewMockBundleReader creates a new mock instance.
func NewMockBundleReader(ctrl *gomock.Controller) *MockBundleReader {
	mock := &MockBundleReader{ctrl: ctrl}
	mock.recorder = &MockBundleReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBundleReader) EXPECT() *MockBundleReaderMockRecorder {
	return m.recorder
}

// ForEachRuleType mocks base method.
func (m *MockBundleReader) ForEachRuleType(arg0 func(*v1.RuleType) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ForEachRuleType", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ForEachRuleType indicates an expected call of ForEachRuleType.
func (mr *MockBundleReaderMockRecorder) ForEachRuleType(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ForEachRuleType", reflect.TypeOf((*MockBundleReader)(nil).ForEachRuleType), arg0)
}

// GetMetadata mocks base method.
func (m *MockBundleReader) GetMetadata() *mindpak.Metadata {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMetadata")
	ret0, _ := ret[0].(*mindpak.Metadata)
	return ret0
}

// GetMetadata indicates an expected call of GetMetadata.
func (mr *MockBundleReaderMockRecorder) GetMetadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMetadata", reflect.TypeOf((*MockBundleReader)(nil).GetMetadata))
}

// GetProfile mocks base method.
func (m *MockBundleReader) GetProfile(arg0 string) (*v1.Profile, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProfile", arg0)
	ret0, _ := ret[0].(*v1.Profile)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetProfile indicates an expected call of GetProfile.
func (mr *MockBundleReaderMockRecorder) GetProfile(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProfile", reflect.TypeOf((*MockBundleReader)(nil).GetProfile), arg0)
}
