package access

type Access uint64

func (a Access) Check(a2 Access) bool {
	return a&a2 == a
}
