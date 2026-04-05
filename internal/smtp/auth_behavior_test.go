package smtp

import (
	"context"
	"errors"
	"testing"

	"github.com/busybox42/elemta/internal/datasource"
	"github.com/stretchr/testify/require"
)

// testAuthFakeDataSource is a test double for datasource.DataSource.
type testAuthFakeDataSource struct {
	authenticateFn func(context.Context, string, string) (bool, error)
}

func (f *testAuthFakeDataSource) Connect() error    { return nil }
func (f *testAuthFakeDataSource) Close() error      { return nil }
func (f *testAuthFakeDataSource) IsConnected() bool { return true }
func (f *testAuthFakeDataSource) Name() string      { return "fake" }
func (f *testAuthFakeDataSource) Type() string      { return "fake" }
func (f *testAuthFakeDataSource) Query(context.Context, string, ...interface{}) (interface{}, error) {
	return nil, nil
}
func (f *testAuthFakeDataSource) Execute(context.Context, string, ...interface{}) error { return nil }
func (f *testAuthFakeDataSource) GetUser(context.Context, string) (datasource.User, error) {
	return datasource.User{}, nil
}
func (f *testAuthFakeDataSource) CreateUser(context.Context, datasource.User) error { return nil }
func (f *testAuthFakeDataSource) UpdateUser(context.Context, datasource.User) error { return nil }
func (f *testAuthFakeDataSource) DeleteUser(context.Context, string) error          { return nil }
func (f *testAuthFakeDataSource) ListUsers(context.Context, map[string]interface{}, int, int) ([]datasource.User, error) {
	return nil, nil
}
func (f *testAuthFakeDataSource) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if f.authenticateFn != nil {
		return f.authenticateFn(ctx, username, password)
	}
	return true, nil
}
func (f *testAuthFakeDataSource) GetPermissions(ctx context.Context, username string) ([]string, error) {
	return nil, nil
}
func (f *testAuthFakeDataSource) HasPermission(ctx context.Context, username string, permission string) (bool, error) {
	return false, nil
}

func TestAuthenticatorBehavior(t *testing.T) {
	tests := []struct {
		name              string
		setup             func() datasource.DataSource
		wantAuthenticated bool
		wantError         bool
	}{
		{
			name: "success",
			setup: func() datasource.DataSource {
				return &testAuthFakeDataSource{
					authenticateFn: func(ctx context.Context, username, password string) (bool, error) {
						return true, nil
					},
				}
			},
			wantAuthenticated: true,
			wantError:         false,
		},
		{
			name: "failure",
			setup: func() datasource.DataSource {
				return &testAuthFakeDataSource{
					authenticateFn: func(ctx context.Context, username, password string) (bool, error) {
						return false, nil
					},
				}
			},
			wantAuthenticated: false,
			wantError:         false,
		},
		{
			name: "error",
			setup: func() datasource.DataSource {
				return &testAuthFakeDataSource{
					authenticateFn: func(ctx context.Context, username, password string) (bool, error) {
						return false, errors.New("db down")
					},
				}
			},
			wantAuthenticated: false,
			wantError:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldFactory := newAuthDataSource
			defer func() { newAuthDataSource = oldFactory }()

			newAuthDataSource = func(cfg datasource.Config) (datasource.DataSource, error) {
				return tt.setup(), nil
			}

			authCfg := &AuthConfig{
				Enabled:        true,
				DataSourceName: "fake",
				DataSourceHost: "fake.internal",
				DataSourcePort: 389,
				DataSourceDB:   "dc=example,dc=com",
			}

			auth, err := NewAuthenticator(authCfg)
			require.NoError(t, err)
			require.NotNil(t, auth)

			ctx := context.Background()
			authenticated, err := auth.Authenticate(ctx, "user", "pass")
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantAuthenticated, authenticated)
		})
	}
}
