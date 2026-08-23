package rbac

var rolePermissions = map[string]map[string]bool{
	"OWNER":           {"*": true},
	"IDENTITY_ADMIN":  {"person.read": true, "person.manage": true, "connector.read": true, "connector.manage": true, "connector.sync": true, "identity.read": true, "identity.link": true, "identity.unlink": true, "lifecycle.read": true, "lifecycle.plan": true},
	"SECURITY_ADMIN":  {"person.read": true, "identity.read": true, "connector.read": true, "lifecycle.read": true, "lifecycle.plan": true, "lifecycle.approve": true, "lifecycle.execute": true, "evidence.read": true, "audit.read": true, "settings.manage": true},
	"ACCESS_REVIEWER": {"person.read": true, "identity.read": true, "access_review.read": true, "access_review.decide": true},
	"OPERATOR":        {"person.read": true, "identity.read": true, "connector.read": true, "connector.sync": true, "lifecycle.read": true, "lifecycle.execute": true},
	"AUDITOR":         {"person.read": true, "connector.read": true, "identity.read": true, "lifecycle.read": true, "access_review.read": true, "evidence.read": true, "audit.read": true},
	"VIEWER":          {"person.read": true, "connector.read": true, "identity.read": true, "lifecycle.read": true, "access_review.read": true},
}

func Allowed(roles []string, permission string) bool {
	for _, role := range roles {
		if rolePermissions[role]["*"] || rolePermissions[role][permission] {
			return true
		}
	}
	return false
}
