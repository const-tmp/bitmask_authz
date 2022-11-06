package authz

import (
	"fmt"
	"github.com/nullc4ts/bitmask_authz/access"
)

const (
	NMax = 64
)

type Authz struct {
	names  map[string]access.Access
	values map[access.Access]string
}

func New(permissions ...string) Authz {
	am := Authz{
		names:  make(map[string]access.Access),
		values: make(map[access.Access]string),
	}
	for i, permission := range permissions {
		if i >= NMax {
			panic("uint64 overflow")
		}
		a := access.Access(1) << i
		am.names[permission] = a
		am.values[a] = permission
	}
	return am
}

func (a Authz) Access(permissions ...string) access.Access {
	ac := access.Access(0)
	for _, permission := range permissions {
		tmp, ok := a.names[permission]
		if !ok {
			panic(fmt.Sprintf("unknown permission: %s", permission))
		}
		ac = ac | tmp
	}
	return ac
}

func (a Authz) ByName() map[string]access.Access {
	return a.names
}

func (a Authz) ByAccess() map[access.Access]string {
	return a.values
}
