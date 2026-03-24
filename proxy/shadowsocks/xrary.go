package shadowsocks

import (
	"net"
	"reflect"
)

const maxDepth = 10

// GetPasswordFromConn 尝试从任意连接对象读取 "password" 元数据。
// 它会按顺序尝试：直接调用 Meta()、调用 Upstream() 递归、尝试常见字段名 (Conn/conn/Inner/inner)。
func GetPasswordFromConn(x any) string {
	return getPasswordRecursive(x, maxDepth)
}

func getPasswordRecursive(x any, depth int) string {
	if x == nil || depth <= 0 {
		return ""
	}

	// 如果是 net.Conn，先查找 Meta()/Upstream() 等
	if nc, ok := x.(net.Conn); ok {
		if pwd := getPasswordFromNetConnReflect(nc); pwd != "" {
			return pwd
		}
	}

	rv := reflect.ValueOf(x)
	if !rv.IsValid() {
		return ""
	}

	// 1) 尝试调用 Meta() 方法
	if m := rv.MethodByName("Meta"); m.IsValid() && m.Type().NumIn() == 0 && m.Type().NumOut() == 1 {
		outs := m.Call(nil)
		if len(outs) == 1 {
			out := outs[0].Interface()
			switch mm := out.(type) {
			case map[string]any:
				if v, ok := mm["password"]; ok {
					if s, ok2 := v.(string); ok2 {
						return s
					}
				}
			case map[string]string:
				if v, ok := mm["password"]; ok {
					return v
				}
			default:
				// 反射访问Map
				rov := reflect.ValueOf(out)
				if rov.IsValid() && rov.Kind() == reflect.Map {
					key := reflect.ValueOf("password")
					val := rov.MapIndex(key)
					if val.IsValid() {
						if val.Kind() == reflect.String {
							return val.String()
						}
						if s, ok := val.Interface().(string); ok {
							return s
						}
					}
				}
			}
		}
	}

	// 2) 尝试 Upstream() 方法
	if u := rv.MethodByName("Upstream"); u.IsValid() && u.Type().NumIn() == 0 && u.Type().NumOut() == 1 {
		outs := u.Call(nil)
		if len(outs) == 1 {
			return getPasswordRecursive(outs[0].Interface(), depth-1)
		}
	}

	// 3) 查找常见字段名
	for _, name := range []string{"Conn", "conn", "Inner", "inner", "Upstream"} {
		f := reflect.Indirect(rv)
		if f.IsValid() {
			if field := f.FieldByName(name); field.IsValid() && field.CanInterface() {
				return getPasswordRecursive(field.Interface(), depth-1)
			}
		}
	}

	// 4) 若是指针或接口，递归其元素
	if rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.Elem().IsValid() {
			return getPasswordRecursive(rv.Elem().Interface(), depth-1)
		}
	}

	return ""
}

func getPasswordFromNetConnReflect(conn net.Conn) string {
	// 1) 尝试断言具有 Meta() 方法
	if mIface, ok := conn.(interface{ Meta() map[string]any }); ok {
		if v, exists := mIface.Meta()["password"]; exists {
			if s, ok2 := v.(string); ok2 {
				return s
			}
		}
	}

	// 2) 尝试 Upstream()
	if u, ok := conn.(interface{ Upstream() any }); ok {
		if inner := u.Upstream(); inner != nil {
			if pwd := getPasswordRecursive(inner, maxDepth-1); pwd != "" {
				return pwd
			}
		}
	}

	// 3) 反射回退尝试（Meta 方法）
	rv := reflect.ValueOf(conn)
	if m := rv.MethodByName("Meta"); m.IsValid() && m.Type().NumIn() == 0 && m.Type().NumOut() == 1 {
		outs := m.Call(nil)
		if len(outs) == 1 {
			out := outs[0]
			if out.Kind() == reflect.Map {
				key := reflect.ValueOf("password")
				val := out.MapIndex(key)
				if val.IsValid() {
					if val.Kind() == reflect.String {
						return val.String()
					}
					if s, ok := val.Interface().(string); ok {
						return s
					}
				}
			}
		}
	}

	return ""
}
