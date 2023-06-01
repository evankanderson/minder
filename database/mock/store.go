// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stacklok/mediator/pkg/db (interfaces: Store)

// Package mockdb is a generated GoMock package.
package mockdb

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	db "github.com/stacklok/mediator/pkg/db"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// CheckHealth mocks base method.
func (m *MockStore) CheckHealth() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckHealth")
	ret0, _ := ret[0].(error)
	return ret0
}

// CheckHealth indicates an expected call of CheckHealth.
func (mr *MockStoreMockRecorder) CheckHealth() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckHealth", reflect.TypeOf((*MockStore)(nil).CheckHealth))
}

// CreateAccessToken mocks base method.
func (m *MockStore) CreateAccessToken(arg0 context.Context, arg1 db.CreateAccessTokenParams) (db.AccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessToken", arg0, arg1)
	ret0, _ := ret[0].(db.AccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAccessToken indicates an expected call of CreateAccessToken.
func (mr *MockStoreMockRecorder) CreateAccessToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessToken", reflect.TypeOf((*MockStore)(nil).CreateAccessToken), arg0, arg1)
}

// CreateGroup mocks base method.
func (m *MockStore) CreateGroup(arg0 context.Context, arg1 db.CreateGroupParams) (db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateGroup", arg0, arg1)
	ret0, _ := ret[0].(db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateGroup indicates an expected call of CreateGroup.
func (mr *MockStoreMockRecorder) CreateGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGroup", reflect.TypeOf((*MockStore)(nil).CreateGroup), arg0, arg1)
}

// CreateOrganisation mocks base method.
func (m *MockStore) CreateOrganisation(arg0 context.Context, arg1 db.CreateOrganisationParams) (db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateOrganisation", arg0, arg1)
	ret0, _ := ret[0].(db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateOrganisation indicates an expected call of CreateOrganisation.
func (mr *MockStoreMockRecorder) CreateOrganisation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateOrganisation", reflect.TypeOf((*MockStore)(nil).CreateOrganisation), arg0, arg1)
}

// CreateRole mocks base method.
func (m *MockStore) CreateRole(arg0 context.Context, arg1 db.CreateRoleParams) (db.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRole", arg0, arg1)
	ret0, _ := ret[0].(db.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateRole indicates an expected call of CreateRole.
func (mr *MockStoreMockRecorder) CreateRole(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRole", reflect.TypeOf((*MockStore)(nil).CreateRole), arg0, arg1)
}

// CreateUser mocks base method.
func (m *MockStore) CreateUser(arg0 context.Context, arg1 db.CreateUserParams) (db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", arg0, arg1)
	ret0, _ := ret[0].(db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockStoreMockRecorder) CreateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockStore)(nil).CreateUser), arg0, arg1)
}

// DeleteAccessToken mocks base method.
func (m *MockStore) DeleteAccessToken(arg0 context.Context, arg1 int32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAccessToken", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAccessToken indicates an expected call of DeleteAccessToken.
func (mr *MockStoreMockRecorder) DeleteAccessToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAccessToken", reflect.TypeOf((*MockStore)(nil).DeleteAccessToken), arg0, arg1)
}

// DeleteGroup mocks base method.
func (m *MockStore) DeleteGroup(arg0 context.Context, arg1 int32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteGroup", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteGroup indicates an expected call of DeleteGroup.
func (mr *MockStoreMockRecorder) DeleteGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteGroup", reflect.TypeOf((*MockStore)(nil).DeleteGroup), arg0, arg1)
}

// DeleteOrganisation mocks base method.
func (m *MockStore) DeleteOrganisation(arg0 context.Context, arg1 int32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOrganisation", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteOrganisation indicates an expected call of DeleteOrganisation.
func (mr *MockStoreMockRecorder) DeleteOrganisation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOrganisation", reflect.TypeOf((*MockStore)(nil).DeleteOrganisation), arg0, arg1)
}

// DeleteRole mocks base method.
func (m *MockStore) DeleteRole(arg0 context.Context, arg1 int32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRole", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRole indicates an expected call of DeleteRole.
func (mr *MockStoreMockRecorder) DeleteRole(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRole", reflect.TypeOf((*MockStore)(nil).DeleteRole), arg0, arg1)
}

// DeleteUser mocks base method.
func (m *MockStore) DeleteUser(arg0 context.Context, arg1 int32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockStoreMockRecorder) DeleteUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockStore)(nil).DeleteUser), arg0, arg1)
}

// GetAccessTokenByOrganisationID mocks base method.
func (m *MockStore) GetAccessTokenByOrganisationID(arg0 context.Context, arg1 int32) (db.AccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessTokenByOrganisationID", arg0, arg1)
	ret0, _ := ret[0].(db.AccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccessTokenByOrganisationID indicates an expected call of GetAccessTokenByOrganisationID.
func (mr *MockStoreMockRecorder) GetAccessTokenByOrganisationID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessTokenByOrganisationID", reflect.TypeOf((*MockStore)(nil).GetAccessTokenByOrganisationID), arg0, arg1)
}

// GetGroupByID mocks base method.
func (m *MockStore) GetGroupByID(arg0 context.Context, arg1 int32) (db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupByID", arg0, arg1)
	ret0, _ := ret[0].(db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupByID indicates an expected call of GetGroupByID.
func (mr *MockStoreMockRecorder) GetGroupByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupByID", reflect.TypeOf((*MockStore)(nil).GetGroupByID), arg0, arg1)
}

// GetGroupByName mocks base method.
func (m *MockStore) GetGroupByName(arg0 context.Context, arg1 string) (db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupByName", arg0, arg1)
	ret0, _ := ret[0].(db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupByName indicates an expected call of GetGroupByName.
func (mr *MockStoreMockRecorder) GetGroupByName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupByName", reflect.TypeOf((*MockStore)(nil).GetGroupByName), arg0, arg1)
}

// GetOrganisation mocks base method.
func (m *MockStore) GetOrganisation(arg0 context.Context, arg1 int32) (db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOrganisation", arg0, arg1)
	ret0, _ := ret[0].(db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOrganisation indicates an expected call of GetOrganisation.
func (mr *MockStoreMockRecorder) GetOrganisation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOrganisation", reflect.TypeOf((*MockStore)(nil).GetOrganisation), arg0, arg1)
}

// GetOrganisationByName mocks base method.
func (m *MockStore) GetOrganisationByName(arg0 context.Context, arg1 string) (db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOrganisationByName", arg0, arg1)
	ret0, _ := ret[0].(db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOrganisationByName indicates an expected call of GetOrganisationByName.
func (mr *MockStoreMockRecorder) GetOrganisationByName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOrganisationByName", reflect.TypeOf((*MockStore)(nil).GetOrganisationByName), arg0, arg1)
}

// GetOrganisationForUpdate mocks base method.
func (m *MockStore) GetOrganisationForUpdate(arg0 context.Context, arg1 string) (db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOrganisationForUpdate", arg0, arg1)
	ret0, _ := ret[0].(db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOrganisationForUpdate indicates an expected call of GetOrganisationForUpdate.
func (mr *MockStoreMockRecorder) GetOrganisationForUpdate(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOrganisationForUpdate", reflect.TypeOf((*MockStore)(nil).GetOrganisationForUpdate), arg0, arg1)
}

// GetRoleByID mocks base method.
func (m *MockStore) GetRoleByID(arg0 context.Context, arg1 int32) (db.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRoleByID", arg0, arg1)
	ret0, _ := ret[0].(db.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoleByID indicates an expected call of GetRoleByID.
func (mr *MockStoreMockRecorder) GetRoleByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoleByID", reflect.TypeOf((*MockStore)(nil).GetRoleByID), arg0, arg1)
}

// GetUserByEmail mocks base method.
func (m *MockStore) GetUserByEmail(arg0 context.Context, arg1 string) (db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByEmail", arg0, arg1)
	ret0, _ := ret[0].(db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByEmail indicates an expected call of GetUserByEmail.
func (mr *MockStoreMockRecorder) GetUserByEmail(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByEmail", reflect.TypeOf((*MockStore)(nil).GetUserByEmail), arg0, arg1)
}

// GetUserByID mocks base method.
func (m *MockStore) GetUserByID(arg0 context.Context, arg1 int32) (db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByID", arg0, arg1)
	ret0, _ := ret[0].(db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByID indicates an expected call of GetUserByID.
func (mr *MockStoreMockRecorder) GetUserByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByID", reflect.TypeOf((*MockStore)(nil).GetUserByID), arg0, arg1)
}

// GetUserByUserName mocks base method.
func (m *MockStore) GetUserByUserName(arg0 context.Context, arg1 string) (db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByUserName", arg0, arg1)
	ret0, _ := ret[0].(db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByUserName indicates an expected call of GetUserByUserName.
func (mr *MockStoreMockRecorder) GetUserByUserName(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByUserName", reflect.TypeOf((*MockStore)(nil).GetUserByUserName), arg0, arg1)
}

// ListGroups mocks base method.
func (m *MockStore) ListGroups(arg0 context.Context, arg1 db.ListGroupsParams) ([]db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListGroups", arg0, arg1)
	ret0, _ := ret[0].([]db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListGroups indicates an expected call of ListGroups.
func (mr *MockStoreMockRecorder) ListGroups(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListGroups", reflect.TypeOf((*MockStore)(nil).ListGroups), arg0, arg1)
}

// ListGroupsByOrganisationID mocks base method.
func (m *MockStore) ListGroupsByOrganisationID(arg0 context.Context, arg1 int32) ([]db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListGroupsByOrganisationID", arg0, arg1)
	ret0, _ := ret[0].([]db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListGroupsByOrganisationID indicates an expected call of ListGroupsByOrganisationID.
func (mr *MockStoreMockRecorder) ListGroupsByOrganisationID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListGroupsByOrganisationID", reflect.TypeOf((*MockStore)(nil).ListGroupsByOrganisationID), arg0, arg1)
}

// ListOrganisations mocks base method.
func (m *MockStore) ListOrganisations(arg0 context.Context, arg1 db.ListOrganisationsParams) ([]db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOrganisations", arg0, arg1)
	ret0, _ := ret[0].([]db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOrganisations indicates an expected call of ListOrganisations.
func (mr *MockStoreMockRecorder) ListOrganisations(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOrganisations", reflect.TypeOf((*MockStore)(nil).ListOrganisations), arg0, arg1)
}

// ListRoles mocks base method.
func (m *MockStore) ListRoles(arg0 context.Context, arg1 db.ListRolesParams) ([]db.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRoles", arg0, arg1)
	ret0, _ := ret[0].([]db.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListRoles indicates an expected call of ListRoles.
func (mr *MockStoreMockRecorder) ListRoles(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRoles", reflect.TypeOf((*MockStore)(nil).ListRoles), arg0, arg1)
}

// ListRolesByGroupID mocks base method.
func (m *MockStore) ListRolesByGroupID(arg0 context.Context, arg1 int32) ([]db.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRolesByGroupID", arg0, arg1)
	ret0, _ := ret[0].([]db.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListRolesByGroupID indicates an expected call of ListRolesByGroupID.
func (mr *MockStoreMockRecorder) ListRolesByGroupID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRolesByGroupID", reflect.TypeOf((*MockStore)(nil).ListRolesByGroupID), arg0, arg1)
}

// ListUsers mocks base method.
func (m *MockStore) ListUsers(arg0 context.Context) ([]db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUsers", arg0)
	ret0, _ := ret[0].([]db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListUsers indicates an expected call of ListUsers.
func (mr *MockStoreMockRecorder) ListUsers(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUsers", reflect.TypeOf((*MockStore)(nil).ListUsers), arg0)
}

// ListUsersByRoleID mocks base method.
func (m *MockStore) ListUsersByRoleID(arg0 context.Context, arg1 int32) ([]db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUsersByRoleID", arg0, arg1)
	ret0, _ := ret[0].([]db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListUsersByRoleID indicates an expected call of ListUsersByRoleID.
func (mr *MockStoreMockRecorder) ListUsersByRoleID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUsersByRoleID", reflect.TypeOf((*MockStore)(nil).ListUsersByRoleID), arg0, arg1)
}

// UpdateAccessToken mocks base method.
func (m *MockStore) UpdateAccessToken(arg0 context.Context, arg1 db.UpdateAccessTokenParams) (db.AccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateAccessToken", arg0, arg1)
	ret0, _ := ret[0].(db.AccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateAccessToken indicates an expected call of UpdateAccessToken.
func (mr *MockStoreMockRecorder) UpdateAccessToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAccessToken", reflect.TypeOf((*MockStore)(nil).UpdateAccessToken), arg0, arg1)
}

// UpdateGroup mocks base method.
func (m *MockStore) UpdateGroup(arg0 context.Context, arg1 db.UpdateGroupParams) (db.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateGroup", arg0, arg1)
	ret0, _ := ret[0].(db.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateGroup indicates an expected call of UpdateGroup.
func (mr *MockStoreMockRecorder) UpdateGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateGroup", reflect.TypeOf((*MockStore)(nil).UpdateGroup), arg0, arg1)
}

// UpdateOrganisation mocks base method.
func (m *MockStore) UpdateOrganisation(arg0 context.Context, arg1 db.UpdateOrganisationParams) (db.Organisation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateOrganisation", arg0, arg1)
	ret0, _ := ret[0].(db.Organisation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateOrganisation indicates an expected call of UpdateOrganisation.
func (mr *MockStoreMockRecorder) UpdateOrganisation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateOrganisation", reflect.TypeOf((*MockStore)(nil).UpdateOrganisation), arg0, arg1)
}

// UpdateRole mocks base method.
func (m *MockStore) UpdateRole(arg0 context.Context, arg1 db.UpdateRoleParams) (db.Role, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateRole", arg0, arg1)
	ret0, _ := ret[0].(db.Role)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateRole indicates an expected call of UpdateRole.
func (mr *MockStoreMockRecorder) UpdateRole(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateRole", reflect.TypeOf((*MockStore)(nil).UpdateRole), arg0, arg1)
}

// UpdateUser mocks base method.
func (m *MockStore) UpdateUser(arg0 context.Context, arg1 db.UpdateUserParams) (db.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", arg0, arg1)
	ret0, _ := ret[0].(db.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockStoreMockRecorder) UpdateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockStore)(nil).UpdateUser), arg0, arg1)
}
