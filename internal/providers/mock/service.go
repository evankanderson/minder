// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stacklok/minder/internal/providers (interfaces: ProviderService)
//
// Generated by this command:
//
//	mockgen -package mockprofsvc -destination internal/providers/mock/service.go github.com/stacklok/minder/internal/providers ProviderService
//

// Package mockprofsvc is a generated GoMock package.
package mockprofsvc

import (
	context "context"
	reflect "reflect"

	db "github.com/stacklok/minder/internal/db"
	providers "github.com/stacklok/minder/internal/providers"
	gomock "go.uber.org/mock/gomock"
	oauth2 "golang.org/x/oauth2"
)

// MockProviderService is a mock of ProviderService interface.
type MockProviderService struct {
	ctrl     *gomock.Controller
	recorder *MockProviderServiceMockRecorder
}

// MockProviderServiceMockRecorder is the mock recorder for MockProviderService.
type MockProviderServiceMockRecorder struct {
	mock *MockProviderService
}

// NewMockProviderService creates a new mock instance.
func NewMockProviderService(ctrl *gomock.Controller) *MockProviderService {
	mock := &MockProviderService{ctrl: ctrl}
	mock.recorder = &MockProviderServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProviderService) EXPECT() *MockProviderServiceMockRecorder {
	return m.recorder
}

// CreateGitHubAppProvider mocks base method.
func (m *MockProviderService) CreateGitHubAppProvider(arg0 context.Context, arg1 oauth2.Token, arg2 db.GetProjectIDBySessionStateRow, arg3 int64, arg4 string) (*db.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateGitHubAppProvider", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*db.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateGitHubAppProvider indicates an expected call of CreateGitHubAppProvider.
func (mr *MockProviderServiceMockRecorder) CreateGitHubAppProvider(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGitHubAppProvider", reflect.TypeOf((*MockProviderService)(nil).CreateGitHubAppProvider), arg0, arg1, arg2, arg3, arg4)
}

// CreateGitHubAppWithoutInvitation mocks base method.
func (m *MockProviderService) CreateGitHubAppWithoutInvitation(arg0 context.Context, arg1 *oauth2.Token, arg2 int64, arg3 providers.ProjectFactory) (*db.ProviderGithubAppInstallation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateGitHubAppWithoutInvitation", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*db.ProviderGithubAppInstallation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateGitHubAppWithoutInvitation indicates an expected call of CreateGitHubAppWithoutInvitation.
func (mr *MockProviderServiceMockRecorder) CreateGitHubAppWithoutInvitation(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGitHubAppWithoutInvitation", reflect.TypeOf((*MockProviderService)(nil).CreateGitHubAppWithoutInvitation), arg0, arg1, arg2, arg3)
}

// CreateGitHubOAuthProvider mocks base method.
func (m *MockProviderService) CreateGitHubOAuthProvider(arg0 context.Context, arg1 string, arg2 db.ProviderClass, arg3 oauth2.Token, arg4 db.GetProjectIDBySessionStateRow, arg5 string) (*db.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateGitHubOAuthProvider", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(*db.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateGitHubOAuthProvider indicates an expected call of CreateGitHubOAuthProvider.
func (mr *MockProviderServiceMockRecorder) CreateGitHubOAuthProvider(arg0, arg1, arg2, arg3, arg4, arg5 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGitHubOAuthProvider", reflect.TypeOf((*MockProviderService)(nil).CreateGitHubOAuthProvider), arg0, arg1, arg2, arg3, arg4, arg5)
}

// ValidateGitHubInstallationId mocks base method.
func (m *MockProviderService) ValidateGitHubInstallationId(arg0 context.Context, arg1 *oauth2.Token, arg2 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateGitHubInstallationId", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateGitHubInstallationId indicates an expected call of ValidateGitHubInstallationId.
func (mr *MockProviderServiceMockRecorder) ValidateGitHubInstallationId(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateGitHubInstallationId", reflect.TypeOf((*MockProviderService)(nil).ValidateGitHubInstallationId), arg0, arg1, arg2)
}
