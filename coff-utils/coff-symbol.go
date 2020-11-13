package coffutils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
)

// ResolveSymbols extract function table information from map and dumpbin output files
func ResolveSymbols(mapfile, dumpbinfile string) (fmap []gtutils.SymbolFuncInfo) {
	var loadBase int
	fmap, loadBase = resolveMap(mapfile)
	resolveDumpbinOut(dumpbinfile, loadBase, fmap)
	return
}

// resolveMap is a function that reads the map file generated by cl and get function info
func resolveMap(fin string) (fmap []gtutils.SymbolFuncInfo, loadBase int) {
	fmap = make([]gtutils.SymbolFuncInfo, 0)
	bin, finerr := os.Open(fin)
	if finerr != nil {
		fmt.Printf("\tFATAL: %s cannot be open\n", fin)
		panic(finerr)
	}
	defer bin.Close()

	loadBase = -1
	var inSymbolTbl bool
	lines := bufio.NewScanner(bin)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())

		if loadBase == -1 &&
			len(fields) >= 5 &&
			fields[0] == "Preferred" &&
			fields[1] == "load" {
			// Load base information
			loadBase64, err := strconv.ParseInt(fields[4], 16, 64)
			if err != nil {
				panic(err)
			}
			loadBase = int(loadBase64)
			continue
		}

		if len(fields) >= 6 &&
			fields[0] == "Address" &&
			fields[1] == "Publics" {
			// Symbol table title, in the format of:
			// Address	Publics by Value	Rva+Base	Lib:Object
			inSymbolTbl = true
			continue
		}

		if !inSymbolTbl {
			continue
		}
		if len(fields) < 4 {
			continue
		}
		if len(strings.Split(fields[0], ":")) != 2 {
			// Symbol Item Physical address pattern: #Sec:#Offset
			continue
		}
		var isFunction bool
		for i := 3; i < len(fields); i++ {
			if fields[i] == "f" {
				isFunction = true
				break
			}
		}
		if !isFunction {
			continue
		}
		memoryAddr64, err := strconv.ParseInt(fields[2], 16, 64)
		if err != nil {
			panic(err)
		}
		fmap = append(fmap, gtutils.SymbolFuncInfo{
			Function:   fields[1],
			HaveSource: true,
			Source:     fields[len(fields)-1],
			Offset:     int(memoryAddr64),
		})
	}

	// .map file groups public and private functions in two groups, so the symbol table needs a sort.
	sort.Slice(fmap, func(i, j int) bool {
		return fmap[i].Offset < fmap[j].Offset
	})
	// Assume that there are no function overlapping
	for i, f := range fmap {
		if i == 0 {
			continue
		}
		idx := i - 1
		fmap[idx].Size = f.Offset - fmap[idx].Offset

	}

	if loadBase == -1 {
		loadBase = 0
	}
	return
}

type sectionRange struct {
	name  string
	start int
	size  int
}

func resolveDumpbinOut(fin string, loadBase int, fmap []gtutils.SymbolFuncInfo) {
	bin, finerr := os.Open(fin)
	if finerr != nil {
		fmt.Printf("\tFATAL: %s cannot be open\n", fin)
		panic(finerr)
	}
	defer bin.Close()

	sections := make([]sectionRange, 0)
	var inFuncTbl bool
	var fmapPointer int
	vAddrRecorded := true
	sizeRawRecorded := true
	nameRecorded := true
	lines := bufio.NewScanner(bin)
	for lines.Scan() {
		line := lines.Text()
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "SECTION HEADER #") {
			vAddrRecorded = false
			sizeRawRecorded = false
			nameRecorded = false
			sections = append(sections, sectionRange{})
			continue
		}
		if strings.HasPrefix(line, "Function Table (") {
			inFuncTbl = true
			continue
		}
		if !inFuncTbl &&
			len(fields) == 2 &&
			nameRecorded == false &&
			fields[1] == "name" {
			// NAME name
			sections[len(sections)-1].name = fields[0]
			nameRecorded = true
		}
		if !inFuncTbl &&
			len(fields) == 3 &&
			sizeRawRecorded == false &&
			fields[1] == "virtual" &&
			fields[2] == "size" {
			// #NUM virtual size
			size64, err := strconv.ParseInt(fields[0], 16, 64)
			if err != nil {
				panic(err)
			}
			sections[len(sections)-1].size = int(size64)
			sizeRawRecorded = true
		}
		if !inFuncTbl &&
			len(fields) == 6 &&
			vAddrRecorded == false &&
			fields[1] == "virtual" &&
			fields[2] == "address" {
			// #NUM virtual address (x-y)
			vaddr64, err := strconv.ParseInt(fields[0], 16, 64)
			if err != nil {
				panic(err)
			}
			sections[len(sections)-1].start = loadBase + int(vaddr64)
			vAddrRecorded = true
		}

		if !inFuncTbl {
			continue
		}
		// Extract function size information
		if len(fields) < 4 {
			continue
		}

		num64 := make([]int64, 4)
		isFunctionItem := true
		var errnum64 error
		for i := 0; i < 4; i++ {
			num64[i], errnum64 = strconv.ParseInt(fields[i], 16, 64)
			if errnum64 != nil {
				isFunctionItem = false
				break
			}
		}
		if !isFunctionItem {
			continue
		}
		start := loadBase + int(num64[1])
		end := loadBase + int(num64[2])
		for ; fmapPointer < len(fmap) &&
			fmap[fmapPointer].Offset <= start; fmapPointer++ {
			var secName string
			for _, sec := range sections {
				if fmap[fmapPointer].Offset >= sec.start && fmap[fmapPointer].Offset+fmap[fmapPointer].Size <= sec.start+sec.size {
					secName = sec.name
					break
				}
			}
			if secName == "" {
				fmt.Printf("WARNING: function %s(%d,0x%x) cannot find a matching section.\n", fmap[fmapPointer].Function, fmap[fmapPointer].Offset, fmap[fmapPointer].Offset)
			} else {
				fmap[fmapPointer].Section = secName
			}

			if fmap[fmapPointer].Offset == start {
				// Check if size can be updated
				size := end - start
				if fmap[fmapPointer].Size != 0 && fmap[fmapPointer].Size < size {
					fmt.Printf("WARNING: function %s has may overlap with the next function\n", fmap[fmapPointer].Function)
				}
				fmap[fmapPointer].Size = size
				fmapPointer++
				break
			}
		}
	}
}

// GenSymbol generate dumpbin symbols using input binary fin into fout dumpbin out file
func GenSymbol(dmISA, fin, fout string) (r string) {
	dumpBinCmd := filepath.Join("/opt/msvc/bin", dmISA, "dumpbin.exe")
	dumpbin := exec.Command(dumpBinCmd, "/RAWDATA:NONE", "/ALL", "/SYMBOLS", fin)
	fmt.Println(dumpbin.String())
	res, errin := dumpbin.Output()
	if errin != nil {
		fmt.Println(dumpbin.Args)
		panic(errin)
	}
	r = string(res)

	bout, fouterr := os.OpenFile(fout, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if fouterr != nil {
		panic(fouterr)
	}
	defer bout.Close()
	if _, err := bout.WriteString(r); err != nil {
		panic(err)
	}

	return
}

//ObjSymbolResolve resolves the dumpbin output symbol of an obj file and grep function information from it.
func ObjSymbolResolve(symbols string) (fmap []gtutils.SymbolFuncInfo) {
	fmap = make([]gtutils.SymbolFuncInfo, 0)
	lines := bufio.NewScanner(strings.NewReader(symbols))
	var inText bool
	var secID int
	secIDtoFMAPIndex := make(map[int]int)
	fMAPIndextoSecID := make([]int, 0)
	for lines.Scan() {
		line := lines.Text()
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "SECTION HEADER #") {
			strNum := strings.TrimPrefix(line, "SECTION HEADER #")
			secID64, err := strconv.ParseInt(strNum, 16, 64)
			if err != nil {
				panic(err)
			}
			secID = int(secID64)
		}
		if line == ".text$mn name" {
			inText = true
			fmap = append(fmap, gtutils.SymbolFuncInfo{
				Section: ".text$mn",
			})
			secIDtoFMAPIndex[secID] = len(fMAPIndextoSecID)
			fMAPIndextoSecID = append(fMAPIndextoSecID, secID)
			continue
		}
		if !inText {
			continue
		}
		if strings.HasPrefix(line, "RELOCATIONS #") ||
			strings.HasPrefix(line, "SECTION HEADER #") {
			inText = false
			continue
		}
		if len(fields) >= 3 &&
			strings.Join(fields[:2], " ") == "COMDAT; sym=" {
			fmap[len(fmap)-1].Function = fields[2]
			continue
		}
		if len(fields) >= 6 &&
			strings.Join(fields[1:6], " ") == "file pointer to raw data" {
			paddr64, err := strconv.ParseInt(fields[0], 16, 64)
			if err != nil {
				panic(err)
			}
			fmap[len(fmap)-1].Offset = int(paddr64)
			continue
		}
		if len(fields) >= 5 &&
			strings.Join(fields[1:5], " ") == "size of raw data" {
			size64, err := strconv.ParseInt(fields[0], 16, 64)
			if err != nil {
				panic(err)
			}
			fmap[len(fmap)-1].Size = int(size64)
			continue
		}
	}

	emptySecID := make(map[int]bool)
	for i, f := range fmap {
		if f.Function == "" {
			emptySecID[fMAPIndextoSecID[i]] = true
		}
	}

	if len(emptySecID) > 0 {
		// dumpbin files generated for /Od are in a different format
		// Functions may need to be read from COFF SYMBOL TABLE
		// The TABLE contains less information than SECTIONS, so it is not preferable
		lines := bufio.NewScanner(strings.NewReader(symbols))
		var inSymbolTable bool
		textMNAddr := make(map[int]int)
		for lines.Scan() {
			line := lines.Text()
			if line == "COFF SYMBOL TABLE" {
				inSymbolTable = true
				continue
			}
			if !inSymbolTable {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 7 && fields[6] == ".text$mn" &&
				strings.HasPrefix(fields[2], "SECT") {
				textMNSec := strings.TrimPrefix(fields[2], "SECT")
				secID64, err := strconv.ParseInt(textMNSec, 16, 64)
				secID = int(secID64)
				if _, ok := emptySecID[secID]; !ok {
					continue
				}
				if err != nil {
					panic(err)
				}
				addr64, err := strconv.ParseInt(fields[1], 16, 64)
				if err != nil {
					panic(err)
				}
				textMNAddr[secID] = int(addr64)
				continue
			}
			// Start check functions
			if len(fields) >= 8 && fields[4] == "()" &&
				strings.HasPrefix(fields[2], "SECT") {
				textMNSec := strings.TrimPrefix(fields[2], "SECT")
				secID64, err := strconv.ParseInt(textMNSec, 16, 64)
				if err != nil {
					panic(err)
				}
				secID = int(secID64)
				if _, ok := textMNAddr[secID]; !ok {
					continue
				}
				fmap = append(fmap, gtutils.SymbolFuncInfo{
					Section: ".text$mn",
				})
				fmap[len(fmap)-1].Function = fields[7]
				addr64, err := strconv.ParseInt(fields[1], 16, 64)
				if err != nil {
					panic(err)
				}
				fmap[len(fmap)-1].Offset = fmap[secIDtoFMAPIndex[secID]].Offset + int(addr64) - textMNAddr[secID]
			}
		}
	}
	return
}