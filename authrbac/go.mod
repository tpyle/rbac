module github.com/tpyle/rbac/authrbac

go 1.26.0

require (
	github.com/tpyle/auth/v2 v2.1.0
	github.com/tpyle/rbac v0.1.0
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// rbac is developed in the parent directory. The replacement only applies
// when building this module itself: consumers use the required version, so
// before tagging authrbac, tag rbac and require that release above.
replace github.com/tpyle/rbac => ../
