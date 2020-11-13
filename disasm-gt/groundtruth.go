package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	coffutils "github.com/pangine/disasm-gt-generator/coff-utils"

	objx86coff "github.com/pangine/pangineDSM-obj-x86-coff"

	elfutils "github.com/pangine/disasm-gt-generator/elf-utils"
	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	objx86elf "github.com/pangine/pangineDSM-obj-x86-elf"
	genutils "github.com/pangine/pangineDSM-utils/general"
)

type instRoot struct {
	offset      int
	predecessor int
}

func main() {
	argNum := len(os.Args)
	InputDir := os.Args[argNum-1]

	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	gnuPrefixFlag := flag.Bool("g", false, "run gnu binutils commands with a 'g' prefix")
	singleTargetFlag := flag.String("sf", "", "only operate on a single file")
	singleDirFlag := flag.String("sd", "", "only operate on a single dir")
	noCheckFuncSizeFlag := flag.Bool("ncfs", false, "do not check function size when matching")
	rvlISAFlag := flag.String("ra", "", "specify a ISA to start llvmmc-resolver (by default it will be auto detected according to input llvm triple)")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")
	flag.Parse()
	llvmTriple := *ltFlag
	singleDir := *singleDirFlag
	singleTarget := *singleTargetFlag
	gnuPrefix := *gnuPrefixFlag
	noCheckFuncSize := *noCheckFuncSizeFlag
	rvlISA := *rvlISAFlag
	printLLVM := *printFlag

	if printLLVM {
		genutils.PrintSupportLlvmTriple(gtutils.LLVMTriples)
		return
	}
	llvmTripleStruct := genutils.ParseLlvmTriple(genutils.CheckLlvmTriple(llvmTriple, gtutils.LLVMTriples))

	binRoot := filepath.Join(InputDir, "bin")
	asmRoot := filepath.Join(InputDir, "s")
	objRoot := filepath.Join(InputDir, "o")
	mthRoot := filepath.Join(InputDir, "match")
	refRoot := filepath.Join(InputDir, "ref")
	gtRoot := filepath.Join(InputDir, "gt")
	_ = os.Mkdir(mthRoot, os.ModePerm)
	_ = os.Mkdir(refRoot, os.ModePerm)
	_ = os.Mkdir(gtRoot, os.ModePerm)

	var dirList []string
	if singleDir != "" {
		dirList = []string{singleDir}
	} else {
		dirList = genutils.GetDirs(binRoot)
	}
	var cntSucc int
	var cntDisc int
	osEnvObj := llvmTripleStruct.OS + "-" + llvmTripleStruct.Env + "-" + llvmTripleStruct.Obj

	if rvlISA == "" {
		rvlISA = llvmTripleStruct.Arch
	}

	fmt.Println("Start llvmmc-resolver...")
	resolver := exec.Command("resolver", "-p", rvlISA)
	resolver.Start()
	time.Sleep(time.Second)

	for _, dir := range dirList {
		fmt.Println("In directory " + dir)
		binDir := filepath.Join(binRoot, dir)
		asmDir := filepath.Join(asmRoot, dir)
		objDir := filepath.Join(objRoot, dir)
		mthDir := filepath.Join(mthRoot, dir)
		refDir := filepath.Join(refRoot, dir)
		gtDir := filepath.Join(gtRoot, dir)
		_ = os.Mkdir(mthDir, os.ModePerm)
		_ = os.Mkdir(refDir, os.ModePerm)
		_ = os.Mkdir(gtDir, os.ModePerm)

		var exeExt string
		switch osEnvObj {
		case "Linux-GNU-ELF":
			// Formalize all assembly files
			elfutils.CleanupLst(asmDir)
			asmFiles := genutils.GetFiles(asmDir, ".s")
			if len(asmFiles) == 0 {
				fmt.Println("\tERROR: No assembly files found")
				cntDisc++
				continue
			}
			fmt.Println("Formalizating assembly files and generate lsts...")
			for _, asm := range asmFiles {
				fm := elfutils.AsmFormalize(asmDir, asm)
				lst := fm[:len(fm)-5] + ".lst"
				elfutils.GenerateLst(asmDir, fm, lst, gnuPrefix, llvmTripleStruct)
			}
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

		aoMap, failed := gtutils.Lst2ObjMatch(osEnvObj, asmDir, objDir)
		if failed {
			fmt.Println("LST to OBJ one to one mapping cannot be found, all binary gt generation failed.")
			cntDisc += len(fileList)
			continue
		}

		for _, file := range fileList {
			fmt.Printf("%s\n", file)

			binFile := filepath.Join(binDir, file)

			mthFile := filepath.Join(mthDir, file+".mth")

			fmt.Println("\t++++++++++ground truth matching++++++++++")
			var insts map[int]gtutils.InsnSupplementary
			var funcs map[gtutils.FuncRow][]int
			var failure bool

			switch osEnvObj {
			case "Linux-GNU-ELF":
				symFile := filepath.Join(refDir, file+".sym")
				symbols := elfutils.GenSymbol(binFile, symFile, gnuPrefix)
				symbolFuncs := elfutils.SymbolResolve(symbols)
				bi := objx86elf.ObjectElf{}.ParseObj(binFile)
				insts, funcs, failure = elfutils.ElfGroundtruthMatch(
					asmDir,
					objDir,
					mthFile,
					file,
					symbolFuncs,
					aoMap,
					bi,
					llvmTripleStruct,
					gnuPrefix,
					noCheckFuncSize,
				)
			case "Win32-MSVC-COFF":
				mapFile := filepath.Join(refDir, strings.TrimSuffix(file, ".exe")+".map")
				dumpbinFile := filepath.Join(refDir, strings.TrimSuffix(file, ".exe")+".dumpbin.out")
				symbolFuncs := coffutils.ResolveSymbols(mapFile, dumpbinFile)
				bi := objx86coff.ObjectCoff{}.ParseObj(binFile)
				insts, funcs, failure = coffutils.CoffGroundtruthMatch(
					asmDir,
					objDir,
					mthFile,
					file,
					symbolFuncs,
					aoMap,
					bi,
					llvmTripleStruct,
					noCheckFuncSize,
				)
			}

			if failure {
				fmt.Println("\t----------discard----------")
				cntDisc++
				continue
			}
			cntSucc++

			fmt.Println("\t++++++++++ground truth generating++++++++++")

			refFile := filepath.Join(gtDir, file+".sqlite")
			gtutils.CreateSqliteGt(refFile, insts, funcs)
			fmt.Println("\t++++++++++done++++++++++")
		}
	}
	fmt.Printf("Succeed: %d, Discard: %d\n", cntSucc, cntDisc)
	resolver.Process.Kill()
}
