package coffutils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	genutils "github.com/pangine/pangineDSM-utils/general"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// CoffGroundtruthMatch is used to generate ground truth on target coff binary file
func CoffGroundtruthMatch(
	asmDir, odjDir, mthFile, binName string,
	symbolFuncs []gtutils.SymbolFuncInfo,
	aoMap map[string]string,
	bi pstruct.BinaryInfo,
	llvmTripleStruct genutils.LlvmTripleStruct,
	noCheckFuncSize bool,
) (
	insts map[int]gtutils.InsnSupplementary,
	funcs map[gtutils.FuncRow][]int,
	failure bool,
) {
	binName = strings.TrimSuffix(binName, ".exe")
	bout, err := os.Create(mthFile)
	if err != nil {
		fmt.Printf("FATAL: mth file %s can not be written.\n", mthFile)
		panic(err)
	}
	defer bout.Close()
	mth := bufio.NewWriter(bout)
	defer mth.Flush()

	// check only functions and sources files that are referenced in symbols
	usedFunc := make(map[string]bool)
	funcCandidates := make(map[string](map[string]bool))
	for _, e := range symbolFuncs {
		if !e.HaveSource {
			continue
		}
		usedFunc[e.Function] = true
		// Can have functions with the same name
		funcCandidates[e.Function] = make(map[string]bool)
	}

	lstFiles := genutils.GetFiles(asmDir, ".cod")
	funcByLst := make(map[string](map[string]*gtutils.LstFunc))
	for _, lst := range lstFiles {
		// Read instructions&labels from LST
		funcMap := ReadLst(asmDir, lst)
		funcByLst[lst] = make(map[string]*gtutils.LstFunc)
		for f := range funcMap {
			// Only record used and non-empty functions
			if usedFunc[f] && len(funcMap[f].InsnAry) > 0 {
				funcCandidates[f][lst] = true
				funcByLst[lst][f] = funcMap[f]
			}
		}
		if len(funcByLst[lst]) == 0 {
			// Remove unused lst
			delete(funcByLst, lst)
		}
	}

	mthLines := make([]string, len(symbolFuncs))
	insts = make(map[int]gtutils.InsnSupplementary)
	funcs = make(map[gtutils.FuncRow][]int)
	usedLst := make(map[string]bool)
	for sID, symbol := range symbolFuncs {
		fName := symbol.Function
		if len(funcCandidates[fName]) == 0 {
			if strings.Index(symbol.Source, ":") < 0 {
				// Source name with ":" are libraries, do not bother then at now.
				fmt.Printf("\tWARNING: no candidates for %s > %s\n",
					symbol.Source, fName)
			}
			continue
		}
		var failToMatch bool
		priorCandidates := make([]string, 0)
		otherCandidates := make([]string, 0)
		for lst := range funcCandidates[fName] {
			fileName := lst[:len(lst)-4]
			sourceName := symbol.Source[:len(symbol.Source)-4]
			if fileName == sourceName {
				//cod that has the same name as the obj source of the function is the 1st priority
				priorCandidates = append([]string{lst}, priorCandidates...)
			} else if usedLst[lst] {
				//cod that contains functions that has already been used by other functions is the 2nd priority
				priorCandidates = append(priorCandidates, lst)
			} else {
				otherCandidates = append(otherCandidates, lst)
			}
		}
		priorCandidates = append(priorCandidates, otherCandidates...)
		for _, lst := range priorCandidates {
			failToMatch = false
			directive, partInsts, partNewRoots :=
				gtutils.MatchForGroundTruth(
					lst,
					bi,
					funcByLst[lst][fName],
					symbol.Offset,
					objx86coff.ObjectCoff{},
					CheckMultipleEncoding,
					false,
				)
			if directive.Result == gtutils.Succeed {
				funcLen := funcByLst[lst][fName].FuncLen
				upbound := pstruct.V2PConv(bi.ProgramHeaders,
					pstruct.P2VConv(bi.ProgramHeaders,
						symbol.Offset)+
						funcLen)
				// Function lengths from dumpbin are not reliable, can only check if there are function overlapping here.
				/*NextSID := sID + 1
				if NextSID < len(symbolFuncs) && upbound > symbolFuncs[NextSID].Offset {
					directive.Result = gtutils.Fail
					fmt.Printf("\tWarning: "+symbol.Source+
						" > "+fName+" < "+lst+
						" is not a match because of function overlapping: %d vs %s:%d\n",
						upbound, symbolFuncs[NextSID].Function, symbolFuncs[NextSID].Offset)
					failToMatch = true
				}*/
				// MSVC generated code can have overlaping functions if necessary. Do not check function length for now.
				mthLines[sID] = symbol.Source + " > " + fName + " < " + lst
				fmt.Println("\t" + mthLines[sID])
				// Locale Aggressive new Root Search
				// TODO: turn off
				gtutils.AggressiveRootSearch(partNewRoots,
					partInsts,
					symbol.Offset,
					upbound,
					bi,
					objx86coff.ObjectCoff{})
				insnLst := make([]int, 0)
				for insn, supplementary := range partInsts {
					insnLst = append(insnLst, insn)
					if _, ok := insts[insn]; !ok {
						insts[insn] = supplementary
					} else {
						// Already have this instruction
						insts[insn] = gtutils.InsnSupplementary{Optional: supplementary.Optional && insts[insn].Optional}
					}
				}
				funcs[gtutils.FuncRow{
					Name:  symbol.Function,
					Start: symbol.Offset,
					End:   upbound,
				}] = insnLst
				usedLst[lst] = true
				break
			} else {
				// Fail or Modify (Windows cod should not have modify)
				fmt.Println("\tINFO: " + symbol.Source +
					" > " + fName + " < " + lst +
					" is not a match")
				failToMatch = true
			}
		}
		if failToMatch {
			if strings.Index(symbol.Source, ":") < 0 {
				fmt.Println("\tERROR: " + symbol.Source + " > " + fName + " cannot find a match\n")
				failure = true
				return
			}
			// The function may come from a library, not existing lst.
			fmt.Println("\tERROR: (WITHHOLD) " + symbol.Source + " > " + fName + " cannot find a match\n")
		}
	}
	// TODO: global new root findings
	for _, matchLine := range mthLines {
		if matchLine == "" {
			continue
		}
		mth.WriteString(matchLine + "\n")
	}
	return
}
