package authz

import (
	"github.com/nullc4ts/bitmask_authz/access"
	"github.com/nullc4ts/bitmask_authz/authz"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBMA(t *testing.T) {
	am := authz.New("access", "read_self", "read_users")
	for s, a := range am.ByName() {
		t.Logf("%s\t%d\t%064b\n", s, a, a)
	}

	a1 := am.Access("access")
	a2 := am.Access("access")
	a3 := am.Access()
	a4 := am.Access("access", "read_self")

	require.True(t, a1.Check(a2))
	require.False(t, a1.Check(a3))
	require.False(t, a4.Check(a3))
	require.False(t, a4.Check(a2))
	require.True(t, a4.Check(a4))
	require.True(t, a4.Check(access.Access(^uint64(0))))

	require.Panics(t, func() {
		a5 := am.Access("sdffsdgd")
		t.Log(a5)
	})
}
