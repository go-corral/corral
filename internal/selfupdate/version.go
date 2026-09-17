package selfupdate

import (
	"strconv"
	"strings"
)

// StripV removes a single leading "v" from a version/tag string.
func StripV(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

type semver struct {
	major, minor, patch int
	pre                 []string
}

// parseSemver parses a bare-or-v-prefixed semver string. ok is false when the core is not
// numeric — an unparseable version (e.g. "dev") is treated as incomparable rather than guessing.
func parseSemver(s string) (v semver, ok bool) {
	s = StripV(s)
	if s == "" {
		return semver{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, v.pre = s[:i], strings.Split(s[i+1:], ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return semver{}, false
	}
	dst := []*int{&v.major, &v.minor, &v.patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		*dst[i] = n
	}
	return v, true
}

// Compare orders two version strings. Returns (-1, 0, +1) and a comparable flag that is false
// when either side is not a parseable semver.
func Compare(a, b string) (cmp int, comparable bool) {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	if !oka || !okb {
		return 0, false
	}
	for _, d := range []int{va.major - vb.major, va.minor - vb.minor, va.patch - vb.patch} {
		if d != 0 {
			return sign(d), true
		}
	}
	return comparePre(va.pre, vb.pre), true
}

func IsNewer(latest, current string) bool {
	cmp, ok := Compare(latest, current)
	return ok && cmp > 0
}

// comparePre orders pre-release lists per SemVer §11: a pre-release ranks below the same core
// without one, then field by field, with a longer list winning ties.
func comparePre(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return sign(len(a) - len(b))
}

func compareIdent(a, b string) int {
	an, aErr := strconv.Atoi(a)
	bn, bErr := strconv.Atoi(b)
	aNumeric, bNumeric := aErr == nil, bErr == nil
	switch {
	case aNumeric && bNumeric:
		return sign(an - bn)
	case aNumeric:
		return -1
	case bNumeric:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
