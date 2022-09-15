package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageLock represents a JavaScript package.lock json file
type PackageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    map[string]Dependency
	Packages        map[string]Package
}

// Dependency represents a single package dependency listed in the package.lock json file
type Dependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

type Package struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	License   string `json:"license"`
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func parsePackageLock(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(path) {
		return nil, nil, nil
	}

	var packages []*pkg.Package
	dec := json.NewDecoder(reader)

	var lock PackageLock
	for {
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
	}

	if lock.LockfileVersion == 1 {
		for name, pkgMeta := range lock.Dependencies {
			packages = append(packages, &pkg.Package{
				Name:     name,
				Version:  pkgMeta.Version,
				Language: pkg.JavaScript,
				Type:     pkg.NpmPkg,
			})
		}
	}

	if lock.LockfileVersion == 2 || lock.LockfileVersion == 3 {
		for name, pkgMeta := range lock.Packages {
			if name == "" {
				continue
			}

			newPackage := &pkg.Package{
				Name:     getNameFromPath(name),
				Version:  pkgMeta.Version,
				Language: pkg.JavaScript,
				Type:     pkg.NpmPkg,
			}

			if pkgMeta.License != "" {
				newPackage.Licenses = []string{pkgMeta.License}
			}

			packages = append(packages, newPackage)
		}
	}

	return packages, nil, nil
}

func getNameFromPath(path string) string {
	parts := strings.Split(path, "node_modules/")
	return parts[len(parts)-1]
}
