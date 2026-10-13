package worker

// OverrideRuntimesForTest replaces the runtime table with specs until the
// returned function is called. Tests use it to see how the build behaves with
// a table that has rows it does not have yet; it is not for production code.
func OverrideRuntimesForTest(specs []RuntimeSpec) (restore func()) {
	saved := runtimeSpecs
	runtimeSpecs = append([]RuntimeSpec(nil), specs...)
	return func() { runtimeSpecs = saved }
}
