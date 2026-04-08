/*
Copyright 2026 The Kubermatic Kubernetes Platform contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package reader

import (
	"go/ast"
	"go/types"
	"log"
	"os"
	"path/filepath"
	"strings"

	"k8c.io/kubermatic/v2/codegen/version-reporter/pkg/config"

	"golang.org/x/tools/go/packages"
)

// AuditImageReferences scans Go packages for corev1.Container Image assignments
// and verifies each references a tracked constant from the config.
// Returns true if all images are tracked, false if any untracked images are found.
func AuditImageReferences(cfg *config.Config) bool {
	tracked := cfg.TrackedGoConstants()
	success := true

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}

	patterns := []string{
		"k8c.io/kubermatic/v2/pkg/resources/...",
		"k8c.io/kubermatic/v2/pkg/controller/...",
	}

	pkgsConfig := &packages.Config{
		Dir:        cwd,
		BuildFlags: []string{"-tags=ee"},
		Mode:       packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedName,
	}

	for _, pattern := range patterns {
		if !auditPackages(pkgsConfig, pattern, tracked) {
			success = false
		}
	}

	return success
}

func auditPackages(cfg *packages.Config, pattern string, tracked map[config.TrackedConstant]string) bool {
	success := true

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		log.Printf("FAIL: failed to load packages for %s: %v", pattern, err)
		return false
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			filename := pkg.Fset.Position(file.Pos()).Filename
			if strings.HasSuffix(filename, "_test.go") {
				continue
			}

			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}

				if !isContainerType(pkg.TypesInfo, lit) {
					return true
				}

				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}

					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != "Image" {
						continue
					}

					if !auditImageExpr(pkg, filename, kv.Value, tracked) {
						success = false
					}
				}

				return true
			})
		}
	}

	return success
}

// isContainerType checks if a composite literal is of type corev1.Container.
func isContainerType(info *types.Info, lit *ast.CompositeLit) bool {
	if info == nil || info.Types == nil {
		return false
	}

	typeInfo, ok := info.Types[lit]
	if !ok {
		return false
	}

	named, ok := typeInfo.Type.(*types.Named)
	if !ok {
		return false
	}

	obj := named.Obj()
	return obj.Pkg() != nil &&
		obj.Pkg().Path() == "k8s.io/api/core/v1" &&
		obj.Name() == "Container"
}

// auditImageExpr checks if an Image value expression references a tracked constant.
// Returns true if the image is tracked or uses no package-level constants (config-based).
// Returns false if any package-level constant is not tracked in versions.yaml.
func auditImageExpr(pkg *packages.Package, filename string, expr ast.Expr, tracked map[config.TrackedConstant]string) bool {
	line := pkg.Fset.Position(expr.Pos()).Line

	// collect all identifiers that resolve to package-level constants
	consts := findConstantRefs(pkg.TypesInfo, expr)
	if len(consts) == 0 {
		// no package-level constants found -- image is built from local variables,
		// method calls, or config fields (customer-overridable)
		log.Printf("SKIP: %s:%d -- no package-level constants (config-based or dynamic)", filepath.Base(filename), line)
		return true
	}

	allTracked := true
	for _, c := range consts {
		if isRegistryPrefix(c.name) {
			continue
		}

		tc := config.TrackedConstant{Package: c.pkgPath, Constant: c.name}
		if productName, ok := tracked[tc]; ok {
			log.Printf("PASS: %s:%d -- %s.%s tracked as %q", filepath.Base(filename), line, shortPkg(c.pkgPath), c.name, productName)
		} else {
			log.Printf("FAIL: %s:%d -- %s.%s is not tracked in versions.yaml", filepath.Base(filename), line, shortPkg(c.pkgPath), c.name)
			allTracked = false
		}
	}

	return allTracked
}

type constRef struct {
	pkgPath string
	name    string
}

// findConstantRefs walks an expression and collects all identifiers that
// resolve to package-level *types.Const.
func findConstantRefs(info *types.Info, expr ast.Expr) []constRef {
	var refs []constRef

	ast.Inspect(expr, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}

		obj := info.Uses[ident]
		if obj == nil {
			return true
		}

		if _, ok := obj.(*types.Const); !ok {
			return true
		}

		if !isPackageLevel(obj) {
			return true
		}

		pkgPath := obj.Pkg().Path()
		refs = append(refs, constRef{pkgPath: pkgPath, name: ident.Name})
		return true
	})

	return refs
}

func isPackageLevel(obj types.Object) bool {
	parent := obj.Parent()
	return parent != nil && strings.HasPrefix(parent.String(), "package ")
}


// isRegistryPrefix returns true for generic registry prefix constants
// like RegistryK8S, RegistryDocker, RegistryQuay that appear in image
// expressions but are not image identifiers themselves.
func isRegistryPrefix(name string) bool {
	switch name {
	case "RegistryK8S", "RegistryDocker", "RegistryQuay", "RegistryGCR", "RegistryMCR":
		return true
	}
	return false
}

func shortPkg(pkgPath string) string {
	return strings.TrimPrefix(pkgPath, "k8c.io/kubermatic/v2/")
}
