package utils

import (
	"fmt"

	genutils "github.com/pangine/pangineDSM-utils/general"
	mcclient "github.com/pangine/pangineDSM-utils/mcclient"
	objectapi "github.com/pangine/pangineDSM-utils/objectAPI"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// LstInsn is a structure used to store instruction information in LSTs
type LstInsn struct {
	Offset  int
	Length  int  // Length of bytes used
	IsAlign bool // Is an align
	Label   string
	Index   int // # of Insn under its label
}

// LstLabel is a structure used to store label information in LSTs
type LstLabel struct {
	Offset int
	Name   string
}

// LstFunc is a struction that collect all insns and labels in a funciton
type LstFunc struct {
	InsnAry  []LstInsn
	LabelAry []LstLabel
	FuncLen  int
	Source   string
}

// InsnRoot records a new root for recursive traversal algorithm to work on
type InsnRoot struct {
	Offset      int
	Predecessor int
}

// MatchResult presents the result of matching functions between LST and binary
type MatchResult int

const (
	// Succeed in matching
	Succeed MatchResult = iota
	// Fail to match
	Fail
	// RequireModify the LST
	RequireModify
)

// MatchDirective shows the directives given for further processes
type MatchDirective struct {
	Result   MatchResult
	Label    string
	Index    int // change the index # instruction under label
	ChangeTo []uint8
}

// MatchForGroundTruth tries to matches input binary and LST in function to
// generate ground truth.
// TODO: turn off align instructions
func MatchForGroundTruth(
	file string,
	bi pstruct.BinaryInfo,
	funcs *LstFunc,
	FuncStart int,
	obj objectapi.Object,
	checkMultipleEncoding func(pstruct.InstFlags, int) bool,
	debug bool,
) (
	directive MatchDirective,
	insnOffsets map[int]InsnSupplementary, // Offsets are in all in Virtual Addresses
	discoveredRoots []InsnRoot,
) {
	data := bi.Sections.Data
	headers := bi.ProgramHeaders
	// Physical Function start address
	phyFuncStart := pstruct.V2PConv(headers, FuncStart)
	directive.Result = Fail
	// Record all known instructions for discovering new roots
	// In virtual addresses
	knownOffsets := make(map[int]bool)
	discoveredRoots = make([]InsnRoot, 0)
	for _, insn := range funcs.InsnAry {
		// Do not directly use FuncStart+offset because
		// There can be a virtual memory gap within a function
		knownOffsets[pstruct.P2VConv(headers, phyFuncStart+insn.Offset)] = true
	}
	// Using labels as roots
	insnOffsets = make(map[int]InsnSupplementary)
	var i int
	for _, label := range funcs.LabelAry {
		if i >= len(funcs.InsnAry) {
			break
		}
		for i < len(funcs.InsnAry) && funcs.InsnAry[i].Label == label.Name {
			insn := funcs.InsnAry[i]
			physicalOffset := phyFuncStart + insn.Offset
			pInstPointer := physicalOffset
			virtualOffset := pstruct.P2VConv(headers, physicalOffset)
			vInstPointer := virtualOffset
			var sizeSum, insnLength int
			var insnStr string
			var insnType pstruct.InstFlags
			for sizeSum == 0 || (insn.IsAlign && sizeSum < insn.Length) {
				// Resolve instruction from file
				res := mcclient.SendResolve(pInstPointer, data)
				if !res.IsInst() || res.TakeBytes() == 0 {
					return
				}
				supplementary := InsnSupplementary{}
				if insn.IsAlign {
					supplementary.Optional = true
				}
				insnOffsets[vInstPointer] = supplementary

				insnLength = int(res.TakeBytes())
				sizeSum += insnLength
				pInstPointer += insnLength
				// Use Physical address to convert to
				// prevent Virtual memory gaps
				vInstPointer = pstruct.P2VConv(headers, pInstPointer)
				var err error
				insnStr, err = res.Inst()
				if err != nil {
					insnStr = "##INST"
				}
				insnType = obj.TypeInst(insnStr, insnLength)
				if insn.IsAlign && !insnType.IsNop {
					// align instructions must be nops
					return
				}
			}
			// Presently only check insn length for matching, should improve this method.
			if sizeSum != insn.Length {
				if insn.IsAlign {
					return
				}
				// Resolved instruction from the file unmatch LST
				// Check if is the multiple encoding cases
				meCase := checkMultipleEncoding(insnType, insn.Length)
				if meCase {
					directive.Result = RequireModify
					directive.Label = label.Name
					directive.Index = insn.Index
					directive.ChangeTo = data[physicalOffset:pInstPointer]
				}
				// For debugging
				if debug {
					fmt.Printf("At virtual address: 0x%x, physical address: 0x%x \n", virtualOffset, physicalOffset)
					fmt.Println("Instruction match debug output:")
					fmt.Printf("Inst: %s\t bin size: %d, lst size: %d\n",
						insnType.OriginInst, insnType.InstSize, insn.Length)
					fmt.Printf("lst at label: %s, index: %d\n",
						insn.Label, insn.Index)
					fmt.Println("binary fragment bytes:")
					for i := physicalOffset; i < pInstPointer; i++ {
						fmt.Printf("0x%02x ", data[i])
					}
					fmt.Println()
				}
				return
			}
			// Aggressive: for none terminative instructions, keep on scanning.
			// Reason: Some nops in icc are presented as data bytes.
			// May genereate overlapping instructions.
			/* for i < len(insns) && !knownOffsets[idx] {
				if insnType.IsHlt || insnType.IsJmp || insnType.IsRet || insnType.IsCall {
					break
				}
				if idx >= len(data) {
					// out of file space
					return
				}
				knownOffsets[idx] = true
				res := mcclient.SendResolve(idx, data)
				if !res.IsInst() || res.TakeBytes() == 0 {
					return
				}
				insnOffsets = append(insnOffsets, idx)
				insnLength = int(res.TakeBytes())
				idx += insnLength
				var err error
				insnStr, err = res.Inst()
				if err != nil {
					insnStr = "##INST"
				}
				fmt.Printf("\t\tAggressive add Insn: %s at %s,%s,%d)\n", insnStr, file, label.name, idx)
				insnType = TypeInst(insnStr, insnLength)
			} */
			// Tries to detect roots that are not recorded in LST
			successors := genutils.InstSuccessors(insnType, vInstPointer)
			for _, s := range successors {
				if !knownOffsets[s] {
					knownOffsets[s] = true
					discoveredRoots = append(discoveredRoots,
						InsnRoot{Offset: s,
							Predecessor: virtualOffset})
				}
			}
			i++
			// Skip unreachable code
			/* if insnType.IsHlt || insnType.IsJmp || insnType.IsRet {
				// "call" is not included because some instructions
				// follow call without a new label
				for i <= len(insns)-1 && insns[i].label == label.name {
					// Skip unreachable instructions
					i++
				}
				break
			} */
		}
	}
	directive.Result = Succeed
	return
}

// AggressiveRootSearch do recursive traversal on input root to find new instrucitons
func AggressiveRootSearch(
	newRootsQue []InsnRoot,
	instMap map[int]InsnSupplementary,
	lowbound, upbound int,
	bi pstruct.BinaryInfo,
	obj objectapi.Object,
) {
	// Aggressively try to discover new instructions from new roots
	// TODO: turn off
	for len(newRootsQue) > 0 {
		root := newRootsQue[0]
		newRootsQue = newRootsQue[1:]
		if _, ok := instMap[root.Offset]; !ok {
			// A new instruction offset
			if root.Offset < lowbound || root.Offset >= upbound {
				continue
			}
			if !pstruct.VAisValid(bi.ProgramHeaders, root.Offset) {
				continue
			}
			phyIP := pstruct.V2PConv(bi.ProgramHeaders, root.Offset)
			if phyIP < 0 || phyIP > len(bi.Sections.Data) {
				// Out of file
				continue
			}
			res := mcclient.SendResolve(phyIP, bi.Sections.Data)
			if !res.IsInst() || res.TakeBytes() == 0 {
				fmt.Printf("\t\tAggressive: fail to resolve instruction at %x, precedessar: %x\n", root.Offset, root.Predecessor)
			} else {
				insnStr, err := res.Inst()
				if err != nil {
					insnStr = "##INST"
				}
				// Aggressive generated instructions are all optional
				supplementary := InsnSupplementary{Optional: true}
				instMap[root.Offset] = supplementary
				fmt.Printf("\t\tAggressive: %x: %s, precedessar: %x\n", root.Offset, insnStr, root.Predecessor)
				insnLength := int(res.TakeBytes())
				insnType := obj.TypeInst(insnStr, insnLength)
				phyIP += insnLength
				vrlIP := pstruct.P2VConv(bi.ProgramHeaders, phyIP)
				successors := genutils.InstSuccessors(insnType, vrlIP)
				for _, s := range successors {
					newRootsQue = append(newRootsQue,
						InsnRoot{Offset: s,
							Predecessor: root.Offset})
				}
			}
		}
	}
}

// Lst2ObjMatch creates a one-to-one match between compiler generated listing files and object file
func Lst2ObjMatch(
	osEnvObj, asmDir, objDir string,
) (
	aoMap map[string]string, failed bool,
) {
	aoMap = make(map[string]string)
	var LstExt, ObjExt string
	switch osEnvObj {
	case "Linux-GNU-ELF":
		LstExt = ".lst"
		ObjExt = ".o"
	case "Win32-MSVC-COFF":
		LstExt = ".cod"
		ObjExt = ".obj"
	default:
		panic("Unsupported llvm files: " + osEnvObj)
	}
	lstFilesList := genutils.GetFiles(asmDir, LstExt)
	objFilesList := genutils.GetFiles(objDir, ObjExt)
	objFilesMap := make(map[string]bool)
	for _, f := range objFilesList {
		objFilesMap[f] = true
	}
	for _, f := range lstFilesList {
		objName := f[:len(f)-len(LstExt)] + ObjExt
		if _, ok := objFilesMap[objName]; !ok {
			fmt.Println("\tERROR: No match for lst: " + f)
			failed = true
			return
		}
		aoMap[f] = objName

	}
	return
}
