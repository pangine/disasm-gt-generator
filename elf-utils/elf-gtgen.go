package elfutils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	genutils "github.com/pangine/pangineDSM-utils/general"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// ElfGroundtruthMatch is used to generate ground truth on target elf binary file
func ElfGroundtruthMatch(
	asmDir, objDir, mthFile, binName string,
	symbolFuncs []gtutils.SymbolFuncInfo,
	aoMap map[string]string,
	bi pstruct.BinaryInfo,
	llvmTripleStruct genutils.LlvmTripleStruct,
	gnuPrefix bool,
	noCheckFuncSize bool,
) (
	insts map[int]gtutils.InsnSupplementary,
	funcs map[gtutils.FuncRow][]int,
	failure bool,
) {
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
	mthLines := make([]string, len(symbolFuncs))
	asmFiles := genutils.GetFiles(asmDir, ".fm.s")
	funcByLst := make(map[string](map[string]*gtutils.LstFunc))
	for _, asm := range asmFiles {
		lst := asm[:len(asm)-5] + ".lst"
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

	// Match asm file with obj file to resolve multiple encoding
	for lst := range funcByLst {
		var obj string
		var ok bool
		if obj, ok = aoMap[lst]; !ok {
			fmt.Printf("\tERROR: no corresponding obj for lst: %s\n",
				lst)
			failure = true
			return
		}
		fmt.Println("----------------------------------------------")
		fmt.Printf("\tMatching lst and obj file: %s <-> %s\n", lst, obj)
		objPath := filepath.Join(objDir, obj)
		objBi := objx86elf.ObjectElf{}.ParseObj(objPath)
		symPath := objPath[:len(objPath)-1] + "sym"
		symbols := GenSymbol(objPath, symPath, gnuPrefix)
		symbolFuncs := SymbolResolve(symbols)
		symbolMap := make(map[string]gtutils.SymbolFuncInfo)
		for _, s := range symbolFuncs {
			if _, ok := symbolMap[s.Function]; ok {
				fmt.Printf("\tERROR: duplicate function in obj: \"%s\"\n",
					s.Function)
				failure = true
				return
			}
			symbolMap[s.Function] = s
		}
		secMap := make(map[string]int)
		for id, name := range objBi.Sections.Name {
			secMap[name] = objBi.Sections.Offset[id]
		}

		symbolSolved := make(map[string]bool)
		var modifyRound int
		// Until all used function in this file is matched
		for len(funcByLst[lst]) > len(symbolSolved) {
			ModifyDirectives := make(map[string]gtutils.MatchDirective)
			ModifyFunc := make(map[string]bool)
			// Match function by function
			for fName, f := range funcByLst[lst] {
				if symbolSolved[fName] {
					continue
				}
				fmt.Printf("\t\t%s: ", fName)
				symbol, ok := symbolMap[fName]
				if !ok {
					fmt.Printf("\tERROR: function does not exist in obj: \"%s\"\n",
						fName)
					failure = true
					return
				}
				secOffset, ok := secMap[symbol.Section]
				if !ok {
					fmt.Printf("\tERROR: section does not exist in obj: \"%s\"\n",
						symbol.Section)
					failure = true
					return
				}
				offset := symbol.Offset + secOffset
				directive, _, _ :=
					gtutils.MatchForGroundTruth(
						lst,
						objBi,
						f,
						offset,
						objx86elf.ObjectElf{},
						CheckMultipleEncoding,
						false,
					)
				switch directive.Result {
				case gtutils.RequireModify:
					// Record this modify directive
					DirectivesMapInsert(ModifyDirectives, directive)
					ModifyFunc[fName] = true
					fmt.Println("modify")
				case gtutils.Succeed:
					symbolSolved[fName] = true
					fmt.Println("succeed")
				case gtutils.Fail:
					// Run again with debug to show the problem
					gtutils.MatchForGroundTruth(
						lst,
						objBi,
						f,
						offset,
						objx86elf.ObjectElf{},
						CheckMultipleEncoding,
						true,
					)
					fmt.Printf("\tERROR: matching lst %s to obj %s failed\n", lst, obj)
					failure = true
					return
				}
			}
			if len(ModifyDirectives) > 0 {
				// Backup and modify asm file
				fm := lst[:len(lst)-4] + ".fm.s"
				bu := lst[:len(lst)-4] + ".mbu.s"
				CopyAsm(asmDir, fm, bu)
				modifyRound++
				fmt.Printf("\tModifying Round #%d for %s\n", modifyRound, fm)
				ModifyAsm(asmDir, fm, ModifyDirectives)
				GenerateLst(asmDir, fm, lst, gnuPrefix, llvmTripleStruct)
				funcMap := ReadLst(asmDir, lst)
				RequiredFuncs := make(map[string]*gtutils.LstFunc)
				for fName := range funcMap {
					if !usedFunc[fName] ||
						len(funcMap[fName].InsnAry) == 0 {
						continue
					}
					RequiredFuncs[fName] = funcMap[fName]
					if !ModifyFunc[fName] &&
						symbolSolved[fName] &&
						!reflect.DeepEqual(*funcByLst[lst][fName], *RequiredFuncs[fName]) {
						// The addition matching process to solve bug: https://sourceware.org/bugzilla/show_bug.cgi?id=25621
						fmt.Printf("\t\tSucceeded function changed after asm modified, rematching: %s > %s\n", lst, fName)
						delete(symbolSolved, fName)
					}
				}
				funcByLst[lst] = RequiredFuncs
			}
		}
	}

	fmt.Println("\n**********************************************")
	fmt.Printf("Matching lsts to binary: %s\n", binName)
	// For each function symbol, search for ground truth in candidates
	insts = make(map[int]gtutils.InsnSupplementary)
	funcs = make(map[gtutils.FuncRow][]int)
	usedLst := make(map[string]bool)
	for sID, symbol := range symbolFuncs {
		fName := symbol.Function
		if len(funcCandidates[fName]) == 0 {
			fmt.Printf("\tWARNING: no candidates for %s > %s\n",
				symbol.Source, fName)
			continue
		}
		var failToMatch bool
		priorCandidates := make([]string, 0)
		otherCandidates := make([]string, 0)
		for lst := range funcCandidates[fName] {
			fileName := lst[:len(lst)-4]
			if usedLst[lst] {
				// lst that has already been used is 1st prioritized
				priorCandidates = append([]string{lst}, priorCandidates...)
			} else {
				// lst contains a prefix or suffix of the executable name is 2nd prioritized
				var FindFix bool
				fields := strings.Split(fileName, "_")
				if strings.HasPrefix(fileName, binName) ||
					strings.HasSuffix(fileName, binName) {
					FindFix = true
				}
				for _, f := range fields {
					if strings.HasPrefix(f, binName) ||
						strings.HasSuffix(f, binName) {
						FindFix = true
						break
					}
				}
				if FindFix {
					priorCandidates = append(priorCandidates, lst)
				} else {
					otherCandidates = append(otherCandidates, lst)
				}
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
				// Allow 0-15 bytes alignment padding
				if !noCheckFuncSize && (upbound-symbol.Offset > symbol.Size ||
					upbound-symbol.Offset+16 <= symbol.Size) {
					directive.Result = gtutils.Fail
					fmt.Printf("\tWarning: "+symbol.Source+
						" > "+fName+" < "+lst+
						" is not a match because of function size: %d (+16) vs %d\n",
						upbound-symbol.Offset, symbol.Size)
					failToMatch = true
				} else {
					mthLines[sID] = symbol.Source + " > " + fName + " < " + lst
					fmt.Println("\t" + mthLines[sID])
					// Locale Aggressive new Root Search
					// TODO: turn off
					gtutils.AggressiveRootSearch(partNewRoots,
						partInsts,
						symbol.Offset,
						upbound,
						bi,
						objx86elf.ObjectElf{})
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
				}
			}
			if directive.Result == gtutils.Fail ||
				directive.Result == gtutils.RequireModify {
				// Dismatch. Restore backups
				fmt.Println("\tINFO: " + symbol.Source +
					" > " + fName + " < " + lst +
					" is not a match")
				failToMatch = true
			}
		}
		if failToMatch {
			// Do not generate real error for now, just log it
			fmt.Println("\tERROR: (WITHHOLD) " + symbol.Source + " > " + fName + " cannot find a match\n")
			//failure = true
			//return
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
