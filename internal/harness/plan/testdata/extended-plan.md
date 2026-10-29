# Tasks: extended plan

**Contract version:** 3
**Work ID:** 0007

## Execution contract

| Component | Root | Regression | Lint | Build | Security | Dev | Health |
|-----------|------|------------|------|-------|----------|-----|--------|
| backend-go | `.` | `go test ./...` | `N/A` | `go build ./...` | `N/A` | `N/A` | `N/A` |
| docs | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` |

## Global gates

### [!] [2.1] Extended

**Requirement:** FR-002
**Depends on:** 1.1
**Behavior:** Renders the extended table
**Components:** backend-go, docs
**Files:** `a.go`
**Implementation files:** `a.go`
**Test files:** 

**RED:**
- `go test ./...` — fails

**Implementation:**
1. Do it

**ACs:**
- [ ] `go test ./...` — passes

**Visual:** REQUIRED
**Documentation:** REQUIRED
