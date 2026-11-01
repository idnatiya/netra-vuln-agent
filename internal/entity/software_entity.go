package entity

// Software is one installed product version, reported for end-of-life checks
// (central compares it against endoflife.date). Path is the binary, package
// file, or project folder it was found in.
type Software struct {
	Name    string
	Version string
	Path    string
}

// Frameworks maps lockfile package names to the product names reported as
// Software. Only these are kept from the full lockfile package list.
var Frameworks = map[string]string{
	"laravel/framework":   "laravel",
	"symfony/http-kernel": "symfony",
	"nuxt":                "nuxt",
	"vue":                 "vue",
	"next":                "next",
	"react":               "react",
	"@angular/core":       "angular",
}
