package middleware

import (
	"context"
	"fmt"
	access2 "github.com/nullc4ts/bitmask_authz/access"
	"github.com/nullc4ts/bitmask_authz/authz"
)

type (
	Endpoint   func(ctx context.Context, i interface{}) (interface{}, error)
	Middleware func(endpoint Endpoint) Endpoint
)

func Factory(a authz.Authz, ctxKey string, permissions ...string) Middleware {
	return func(next Endpoint) Endpoint {
		return func(ctx context.Context, i interface{}) (interface{}, error) {
			access := ctx.Value(ctxKey)
			if access == nil {
				return nil, fmt.Errorf("access not found in context")
			}
			ac, ok := access.(access2.Access)
			if !ok {
				return nil, fmt.Errorf("access=%+v %T is not type Access", access, access)
			}
			if !a.Access(permissions...).Check(ac) {
				return nil, fmt.Errorf("permission denied")
			}
			return next(ctx, i)
		}
	}
}
