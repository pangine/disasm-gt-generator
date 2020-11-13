package utils

// SymbolFuncInfo record the information about a function record in symbol
type SymbolFuncInfo struct {
	Function   string
	HaveSource bool
	Source     string
	Offset     int
	Size       int
	Line       int
	Section    string
}
