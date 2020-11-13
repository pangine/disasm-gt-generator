package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	objectsapi "github.com/pangine/pangineDSM-utils/objectAPI"

	coffutils "github.com/pangine/disasm-gt-generator/coff-utils"
	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"

	elfutils "github.com/pangine/disasm-gt-generator/elf-utils"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	genutils "github.com/pangine/pangineDSM-utils/general"
	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

type checkFunc struct {
	lstPath string
	objPath string
	f       string
	offset  int
}

func readMth(
	mthFile string,
	gtFuncLen int,
) (
	func2lst map[string]([]string),
	lst2func map[string]([]string),
	failed bool,
) {
	func2lst = make(map[string]([]string))
	lst2func = make(map[string]([]string))
	fin, finerr := os.Open(mthFile)
	if finerr != nil {
		panic(mthFile + " does not exist.")
	}
	defer fin.Close()

	lines := bufio.NewScanner(fin)
	var mthLines int
	for lines.Scan() {
		line := lines.Text()
		indexGreaterT := strings.LastIndex(line, "<")
		indexLessT := strings.Index(line, ">")
		if indexGreaterT < 0 || indexLessT < 0 {
			continue
		}
		mthLines++
		funcName := line[indexLessT+2 : indexGreaterT-1]
		lstName := line[indexGreaterT+2:]
		if _, ok := func2lst[funcName]; !ok {
			func2lst[funcName] = make([]string, 0)
		}
		func2lst[funcName] = append(func2lst[funcName], lstName)
		if _, ok := lst2func[lstName]; !ok {
			lst2func[lstName] = make([]string, 0)
		}
		lst2func[lstName] = append(lst2func[lstName], funcName)
	}

	if mthLines != gtFuncLen {
		fmt.Printf("\tERROR: gt and mth func number does not match: %d vs %d",
			gtFuncLen, mthLines)
		failed = true
	}
	return
}

func checkGt(
	asmDir, objDir, binFile, osEnvObj string,
	aoMap map[string]string,
	func2lst map[string][]string,
	lst2func map[string][]string,
	gtFuncs []gtutils.FuncRow,
	gnuPrefix bool,
	dmISA string,
) (
	insns map[int]bool,
	failed bool,
) {
	insns = make(map[int]bool)
	funcByLst := make(map[string](map[string]*gtutils.LstFunc))
	checkFuncByLst := make(map[string]([]checkFunc))
	for _, f := range gtFuncs {
		if list, ok := func2lst[f.Name]; !ok || len(list) == 0 {
			fmt.Printf("\tERROR: function does not found in lst: \"%s\" from %d\n",
				f.Name, f.Start)
			failed = true
			return
		}
		// use the order in mth file if there are dup func names
		lstName := func2lst[f.Name][0]
		func2lst[f.Name] = func2lst[f.Name][1:]
		var objName string
		var ok bool
		if objName, ok = aoMap[lstName]; !ok {
			fmt.Printf("\tERROR: no corresponding obj for lst: \"%s\" > %s\n",
				lstName, f.Name)
			failed = true
			return
		}
		fmt.Printf("\tRecord function %s > %s < %s\n", objName, f.Name, lstName)
		lstPath := filepath.Join(asmDir, lstName)
		objPath := filepath.Join(objDir, objName)
		if _, ok = funcByLst[lstName]; !ok {
			// Not yet converted and read
			checkFuncByLst[lstName] = make([]checkFunc, 0)
			var funcMap map[string]*gtutils.LstFunc
			switch osEnvObj {
			case "Linux-GNU-ELF":
				funcMap = elfutils.ReadLst(asmDir, lstName)
			case "Win32-MSVC-COFF":
				funcMap = coffutils.ReadLst(asmDir, lstName)
			}
			funcByLst[lstName] = make(map[string]*gtutils.LstFunc)
			for _, fn := range lst2func[lstName] {
				funcByLst[lstName][fn] = funcMap[fn]
			}
		}
		checkFuncByLst[lstName] = append(checkFuncByLst[lstName],
			checkFunc{
				lstPath: lstPath,
				objPath: objPath,
				f:       f.Name,
				offset:  f.Start,
			})
	}

	// check by lst
	var object objectsapi.Object
	var multipleEncodingFunc func(pstruct.InstFlags, int) bool
	switch osEnvObj {
	case "Linux-GNU-ELF":
		object = objx86elf.ObjectElf{}
		multipleEncodingFunc = elfutils.CheckMultipleEncoding
	case "Win32-MSVC-COFF":
		object = objx86coff.ObjectCoff{}
		multipleEncodingFunc = coffutils.CheckMultipleEncoding
	}
	bi := object.ParseObj(binFile)
	for lst, cfList := range checkFuncByLst {
		if len(cfList) == 0 {
			continue
		}
		lstPath := cfList[0].lstPath
		objPath := cfList[0].objPath
		fmt.Printf("\tIn %s (%s)\n", lstPath, objPath)
		objBi := object.ParseObj(objPath)
		var symbolFuncs []gtutils.SymbolFuncInfo
		switch osEnvObj {
		case "Linux-GNU-ELF":
			symPath := objPath[:len(objPath)-1] + "sym"
			symbols := elfutils.GenSymbol(objPath, symPath, gnuPrefix)
			symbolFuncs = elfutils.SymbolResolve(symbols)
		case "Win32-MSVC-COFF":
			symPath := objPath[:len(objPath)-3] + "dumpbin.out"
			symbols := coffutils.GenSymbol(dmISA, objPath, symPath)
			symbolFuncs = coffutils.ObjSymbolResolve(symbols)
		}
		// Translate symbolFuncs list into map, only keep func offset
		symbolMap := make(map[string]gtutils.SymbolFuncInfo)
		for _, s := range symbolFuncs {
			if _, ok := symbolMap[s.Function]; ok {
				fmt.Printf("\tERROR: duplicate function in obj: \"%s\"\n",
					s.Function)
				failed = true
				return
			}
			symbolMap[s.Function] = s
		}
		secMap := make(map[string]int)
		for id, name := range objBi.Sections.Name {
			secMap[name] = objBi.Sections.Offset[id]
		}
		for _, cf := range cfList {
			fName := cf.f
			fmt.Printf("\t\t%s: ", fName)
			symbol, ok := symbolMap[fName]
			if !ok {
				fmt.Printf("\tERROR: function does not exist in obj: \"%s\"\n",
					fName)
				failed = true
				return
			}
			secOffset, ok := secMap[symbol.Section]
			if !ok {
				fmt.Printf("\tERROR: section does not exist in obj: \"%s\"\n",
					symbol.Section)
				failed = true
				return
			}
			// nm on object file by defaut is separate by each section
			// so needs to add the base
			var offset int
			switch osEnvObj {
			case "Linux-GNU-ELF":
				offset = symbol.Offset + secOffset
			case "Win32-MSVC-COFF":
				offset = symbol.Offset
			}
			directive, partInsts, _ :=
				gtutils.MatchForGroundTruth(
					lst,
					objBi,
					funcByLst[lst][fName],
					offset,
					object,
					multipleEncodingFunc,
					true,
				)
			if directive.Result != gtutils.Succeed {
				fmt.Println("failed")
				failed = true
				return
			}
			for i := range partInsts {
				// Translate from obj file space to binary file space
				insns[pstruct.P2VConv(bi.ProgramHeaders,
					pstruct.V2PConv(objBi.ProgramHeaders, i)-
						pstruct.V2PConv(objBi.ProgramHeaders, offset)+
						pstruct.V2PConv(bi.ProgramHeaders, cf.offset))] = true
			}
			fmt.Println("pass")
		}
	}
	return
}

func checkInsn(ckInsn map[int]bool, gtInsn map[int]gtutils.InsnSupplementary) bool {
	var usedInsn int
	fmt.Println("\tCheck if check insn matches the generated ground truth")
	for i, s := range gtInsn {
		if ckInsn[i] {
			usedInsn++
			continue
		}
		if !s.Optional {
			fmt.Printf("\tERROR: %d is not optional and is not checked", i)
			return true
		}
	}
	if usedInsn != len(ckInsn) {
		fmt.Printf("\tERROR: insns checked but not in gt: %d vs %d", usedInsn, len(ckInsn))
		return true
	}
	fmt.Println("\tALL-PASS: all non-optional instructions in gt have been checked")
	return false
}

func main() {
	argNum := len(os.Args)
	InputDir := os.Args[argNum-1]

	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	gnuPrefixFlag := flag.Bool("g", false, "run gnu binutils commands with a 'g' prefix")
	singleTargetFlag := flag.String("sf", "", "only operate on a single file")
	singleDirFlag := flag.String("sd", "", "only operate on a single dir")
	rvlISAFlag := flag.String("ra", "", "specify a ISA to start llvmmc-resolver (by default it will be auto detected according to input llvm triple)")
	dmISAFlag := flag.String("dm", "", "specify the dumpbin version to use for windows binaries [x64, x86] (by default it will be auto detected according to input llvm triple)")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")

	flag.Parse()
	llvmTriple := *ltFlag
	singleDir := *singleDirFlag
	singleTarget := *singleTargetFlag
	gnuPrefix := *gnuPrefixFlag
	printLLVM := *printFlag
	dmISA := *dmISAFlag
	rvlISA := *rvlISAFlag
	if printLLVM {
		genutils.PrintSupportLlvmTriple(gtutils.LLVMTriples)
		return
	}
	llvmTripleStruct := genutils.ParseLlvmTriple(genutils.CheckLlvmTriple(llvmTriple, gtutils.LLVMTriples))
	osEnvObj := llvmTripleStruct.OS + "-" + llvmTripleStruct.Env + "-" + llvmTripleStruct.Obj

	if rvlISA == "" {
		rvlISA = llvmTripleStruct.Arch
	}

	fmt.Println("Start llvmmc-resolver...")
	resolver := exec.Command("resolver", "-p", rvlISA)
	resolver.Start()
	time.Sleep(time.Second)

	if dmISA == "" {
		switch llvmTripleStruct.Arch {
		case "x86":
			dmISA = "x86"
		case "x86_64":
			dmISA = "x64"
		}
	}

	binRoot := filepath.Join(InputDir, "bin")
	asmRoot := filepath.Join(InputDir, "s")
	objRoot := filepath.Join(InputDir, "o")
	mthRoot := filepath.Join(InputDir, "match")
	gtRoot := filepath.Join(InputDir, "gt")

	var dirList []string
	if singleDir != "" {
		dirList = []string{singleDir}
	} else {
		dirList = genutils.GetDirs(binRoot)
	}
	var cntSucc int
	var cntFail int

	for _, dir := range dirList {

		binDir := filepath.Join(binRoot, dir)
		asmDir := filepath.Join(asmRoot, dir)
		objDir := filepath.Join(objRoot, dir)
		mthDir := filepath.Join(mthRoot, dir)
		gtDir := filepath.Join(gtRoot, dir)

		var exeExt string
		switch osEnvObj {
		case "Linux-GNU-ELF":
			exeExt = ""
		case "Win32-MSVC-COFF":
			exeExt = ".exe"
		}
		var fileList []string
		if singleTarget != "" && singleDir != "" {
			fileList = []string{singleTarget}
		} else {
			fileList = genutils.GetFiles(binDir, exeExt)
		}

		for _, file := range fileList {
			fmt.Println("\t+++++++++++++++++++++++++++++++++++++++++")
			fmt.Printf("%s\n", file)
			fmt.Println("\t++++++++++ground truth checking++++++++++")
			aoMap, failed := gtutils.Lst2ObjMatch(osEnvObj, asmDir, objDir)
			if failed {
				cntFail++
				continue
			}
			gtFile := filepath.Join(gtDir, file+".sqlite")
			gtFuncs := gtutils.ReadSqliteGtFuncInOrder(gtFile)
			mthFile := filepath.Join(mthDir, file+".mth")
			func2lst, lst2func, failed := readMth(mthFile, len(gtFuncs))
			if failed {
				cntFail++
				continue
			}
			// Check gt using by matching lst to obj in functions
			ckInsn, failed := checkGt(
				asmDir,
				objDir,
				filepath.Join(binDir, file),
				osEnvObj,
				aoMap, func2lst, lst2func, gtFuncs, gnuPrefix, dmISA)
			if failed {
				cntFail++
				continue
			}
			gtInsn, _ := gtutils.ReadSqliteGt(gtFile)

			failed = checkInsn(ckInsn, gtInsn)
			if failed {
				cntFail++
				continue
			}
			cntSucc++
		}
	}
	fmt.Printf("Succeed: %d, Failed: %d\n", cntSucc, cntFail)
	resolver.Process.Kill()
}
