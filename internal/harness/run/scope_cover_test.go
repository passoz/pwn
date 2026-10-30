package run

import "testing"

func TestGlobsMayOverlapMalformedPatternOnEitherSideIsConservative(t *testing.T) {
	// O literal está do lado oposto ao de scope_test.go: o glob malformado é o
	// segundo argumento e o literal é o primeiro.
	if !GlobsMayOverlap("src/a", "src/{a") {
		t.Fatal("literal contra glob malformado deveria ser tratado como sobreposição")
	}
	if !GlobsMayOverlap("src/{a", "src/a") {
		t.Fatal("glob malformado contra literal deveria ser tratado como sobreposição")
	}
	// Prefixos literais divergentes continuam disjuntos mesmo com padrão malformado.
	if GlobsMayOverlap("docs/a", "src/{a") {
		t.Fatal("prefixos disjuntos não podem sobrepor, mesmo com glob malformado")
	}
}
