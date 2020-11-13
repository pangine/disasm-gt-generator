package coffutils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// Ref: https://docs.microsoft.com/en-us/cpp/assembler/inline/data-directives-and-operators-in-inline-assembly?view=vs-2019
var dataDirectives = map[string]bool{
	// data
	"DB":     true,
	"DW":     true,
	"DD":     true,
	"DQ":     true,
	"DT":     true,
	"DF":     true,
	"STRUC":  true,
	"RECORD": true,
	"WIDTH":  true,
	"MASK":   true,
}

// ReadLst in coffutils read the cod input and output the instructions and labels information
func ReadLst(
	path, file string,
) (
	funcMap map[string]*gtutils.LstFunc,
) {
	file = filepath.Join(path, file)
	bin, finerr := os.Open(file)
	if finerr != nil {
		fmt.Printf("\tFATAL: %s cannot be open\n", file)
		panic(finerr)
	}
	defer bin.Close()
	funcMap = make(map[string]*gtutils.LstFunc)

	// First iteration
	procList := make(map[string]bool)
	funcList := make(map[string]bool)
	// A function in cod file is defined using a pair of
	// 	func_name PROC
	// 	func_name ENDP
	// symbols.
	lines := bufio.NewScanner(bin)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 2 {
			continue
		}
		if strings.HasPrefix(fields[0], ";") ||
			strings.HasPrefix(fields[1], ";") {
			continue
		}
		if fields[1] == "PROC" {
			procList[fields[0]] = true
			continue
		}
		if fields[1] == "ENDP" &&
			procList[fields[0]] {
			funcList[fields[0]] = true
		}
	}
	// Reset scanner
	bin.Seek(0, io.SeekStart)

	// Second iteration, record instructions and labels in functions
	var inTextSection, inFunction, lastIsAlign, lastNotFinished bool
	var fName, lName string
	var insnOffset, insnBytes, labelIndex int
	lines = bufio.NewScanner(bin)
	for lines.Scan() {
		line := lines.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// In _TEXT section, between a pair of
		// 	_TEXT SEGMENT
		// 	_TEXT ENDS
		if fields[0] == "_TEXT" &&
			len(fields) >= 2 &&
			fields[1] == "SEGMENT" {
			inTextSection = true
			continue
		}
		if inTextSection &&
			len(fields) >= 2 &&
			fields[0] == "_TEXT" &&
			fields[1] == "ENDS" {
			inTextSection = false
			continue
		}

		// Only extract functions in text section for now
		// Start of a function
		if inTextSection &&
			len(fields) >= 2 &&
			fields[1] == "PROC" &&
			funcList[fields[0]] {
			fName = fields[0]
			funcMap[fName] = &gtutils.LstFunc{}
			inFunction = true
			// In case of a function without a first label, should not happen though
			lName = fields[0]
			labelIndex = 0
			lastIsAlign = false
			lastNotFinished = false
			continue
		}
		// End of a function
		if inTextSection &&
			len(fields) >= 2 &&
			fields[1] == "ENDP" &&
			fields[0] == fName {
			fName = fields[0]
			inFunction = false
			lastIsAlign = false
			lastNotFinished = false
			continue
		}

		// Do not care about data sections for now.
		if !inFunction || !inTextSection {
			continue
		}

		firstNumber64, err := strconv.ParseInt(fields[0], 16, 64)
		if err != nil {
			// Not an instruction
			if strings.HasPrefix(fields[0], "$") &&
				// Check if it is a label
				strings.HasSuffix(fields[0], ":") {
				lName = fields[0]
				labelIndex = 0
				lastIsAlign = false
				lastNotFinished = false
			} else if funcMap[fName].Source == "" &&
				strings.HasPrefix(line, "; File ") {
				// Is a file directive
				source := line[7:]
				cutFrom := strings.LastIndex(source, "\\")
				cutFrom++
				funcMap[fName].Source = source[cutFrom:]
			}
			continue
		}

		// An insn line consists of "offset \t mc bytes \t(s) assembly inssn (\t(s) comments)"
		// For a long insn, there can be a return in "mc bytes" field,
		// and the "offset" in the next line will be empty
		frames := strings.Split(line, "\t")
		bytesFrame := 1
		if !strings.HasPrefix(line, "\t") {
			if !lastNotFinished {
				insnOffset = int(firstNumber64)
				insnBytes = 0
			}
		}
		bytesInFrame := strings.Fields(frames[bytesFrame])
		for _, b := range bytesInFrame {
			// Count number of bytes used
			_, err := strconv.ParseInt(b, 16, 32)
			if err == nil && len(b) == 2 {
				insnBytes++
			} else {
				fmt.Println(fName)
				fmt.Println(inFunction, inTextSection)
				panic("Parse cod error (Bytes field incorrect): " + line)
			}
		}
		// Increase the function length
		funcMap[fName].FuncLen = insnOffset + insnBytes
		lastNotFinished = true
		breakSign := ""
		lastPiece := ""
		var meetComment bool
		for i := bytesFrame + 1; i < len(frames) && !meetComment; i++ {
			// Check if the the "insn" is actually a constant data
			stringsInFrame := strings.Fields(frames[i])
			for _, s := range stringsInFrame {
				if strings.HasPrefix(s, ";") {
					// Comment til the end
					if breakSign == "" {
						breakSign = s
					}
					meetComment = true
					break
				}
				lastPiece = s
				if s != "" && breakSign == "" {
					// The other characters are all considered as "insns"
					breakSign = s
					lastNotFinished = false
				}
			}
		}
		if dataDirectives[breakSign] {
			// Not really insn, it is a data piece.
			// Ignore it for now
			continue
		}
		if _, ok := objx86coff.PrefixMap[lastPiece]; ok {
			// lastPiece is a prefix instruction, need to connect with the next instruction
			lastNotFinished = true
		}
		if !lastNotFinished {
			if labelIndex == 0 {
				funcMap[fName].LabelAry = append(
					funcMap[fName].LabelAry,
					gtutils.LstLabel{
						Offset: insnOffset,
						Name:   lName,
					},
				)
			}
			var isAlign bool
			if breakSign == "npad" {
				// It is a nop
				if lastIsAlign {
					// Append to the last nop
					funcMap[fName].InsnAry[len(funcMap[fName].InsnAry)-1].Length += insnBytes
					continue
				}
				isAlign = true
				lastIsAlign = true
			} else {
				lastIsAlign = false
			}
			if breakSign != "" && insnBytes > 0 {
				funcMap[fName].InsnAry = append(funcMap[fName].InsnAry,
					gtutils.LstInsn{
						Offset:  insnOffset,
						Length:  insnBytes,
						IsAlign: isAlign,
						Label:   lName,
						Index:   labelIndex,
					},
				)
				labelIndex++
			}
		}
	}

	// remove tail align
	for f, v := range funcMap {
		var removeInsn, removeLabel int
		for i := len(v.InsnAry) - 1; i >= 0; i-- {
			if v.InsnAry[i].IsAlign == false {
				break
			}
			removeInsn++
			if v.InsnAry[i].Index == 0 {
				removeLabel++
			}
		}
		funcMap[f].InsnAry = funcMap[f].InsnAry[:len(v.InsnAry)-removeInsn]
		funcMap[f].LabelAry = funcMap[f].LabelAry[:len(funcMap[f].LabelAry)-removeLabel]
	}
	return
}

// CheckMultipleEncoding in windows should not have multiple encoding cases
func CheckMultipleEncoding(insn pstruct.InstFlags, lstInsnSize int) bool {
	return false
}
