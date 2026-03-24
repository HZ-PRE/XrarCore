package shadowsocks

import (
	"net"
	"reflect"
)

// tryMetaIface 用于断言任意实现了 Meta() map[string]any 的对象
type metaIface interface {
	Meta() map[string]any
}

// tryUpstream 用于处理常见包装 —— 返回底层 Upstream() any
type upstreamIface interface {
	Upstream() any
}

// GetPasswordFromConn tries to find a Meta() map on the conn (or its upstreams) and return "password".
// It does not require external deps.
func GetPasswordFromConn(conn net.Conn) string {
	return getPasswordFromConnRecursive(conn, 8)
}

func getPasswordFromConnRecursive(conn net.Conn, depth int) string {
	if conn == nil || depth <= 0 {
		return ""
	}

	// 1) direct type assertion to local metaIface
	if m, ok := conn.(metaIface); ok {
		if v, exists := m.Meta()["password"]; exists {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}

	// 2) try upstreamer interface (common in wrappers)
	if u, ok := conn.(upstreamIface); ok {
		up := u.Upstream()
		if upConn, ok := up.(net.Conn); ok {
			if pwd := getPasswordFromConnRecursive(upConn, depth-1); pwd != "" {
				return pwd
			}
		}
	}

	// 3) safe reflect fallback: try call Meta() method by name (in case it is not in same package type)
	rv := reflect.ValueOf(conn)
	// if it's a pointer/interface, try to get the underlying element(s)
	for i := 0; i < 4 && rv.IsValid(); i++ {
		if rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
			rv = rv.Elem()
			continue
		}
		break
	}
	if !rv.IsValid() {
		return ""
	}

	// try find method named "Meta"
	m := reflect.ValueOf(conn).MethodByName("Meta")
	if m.IsValid() && m.Type().NumIn() == 0 && m.Type().NumOut() == 1 {
		outs := m.Call(nil)
		if len(outs) == 1 {
			out := outs[0]
			// Expecting map[string]any
			if out.Kind() == reflect.Map {
				// convert to map[string]any via iteration
				for _, k := range out.MapKeys() {
					if k.Kind() == reflect.String && k.String() == "password" {
						v := out.MapIndex(k)
						if v.IsValid() && v.Kind() == reflect.String {
							return v.String()
						} else if v.IsValid() {
							// try to convert via Interface()
							if s, ok := v.Interface().(string); ok {
								return s
							}
						}
					}
				}
			} else if out.Kind() == reflect.Interface || out.Kind() == reflect.Ptr {
				if mm, ok := out.Interface().(map[string]any); ok {
					if v, exists := mm["password"]; exists {
						if s, ok2 := v.(string); ok2 {
							return s
						}
					}
				}
			}
		}
	}

	return ""
}
