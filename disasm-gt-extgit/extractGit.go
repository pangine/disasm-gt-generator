package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
	genutils "github.com/pangine/pangineDSM-utils/general"
)

var sdir string = "s/"
var odir string = "o/"
var refdir string = "ref/"
var builddir string = "build/"

var asmsuffix string
var objsuffix string

func removeFilePath(pathName string) (file string) {
	lastSlash := strings.LastIndex(pathName, "/")
	file = pathName[lastSlash+1:]
	return
}

func getFileName(pathName string) (file string) {
	lastSlash := strings.LastIndex(pathName, "/")
	lastDot := strings.LastIndex(pathName, ".")
	if lastDot <= lastSlash+1 {
		lastDot = len(pathName)
	}
	file = pathName[lastSlash+1 : lastDot]
	return
}

func getFilePath(pathName string) (path string) {
	lastSlash := strings.LastIndex(pathName, "/")
	path = pathName[:lastSlash+1]
	return
}

func copyFilesToDir(
	buildDir string,
	files []string,
	dir string,
	renameFiles map[string]string,
	useOriginalName bool,
	ext string,
) {
	for _, file := range files {
		dfile := file
		if _, ok := renameFiles[file]; ok {
			dfile = renameFiles[file]
		}
		originFile := filepath.Join(buildDir, file)
		var dstName string
		if !useOriginalName {
			fileName := getFileName(dfile)
			dstName = filepath.Join(dir, fileName+ext)
			var counter int
			for fileExists(dstName) {
				counter++
				dstName = filepath.Join(dir, fileName+"_gt"+strconv.Itoa(counter)+ext)
			}
		} else {
			fileName := removeFilePath(dfile)
			dstName = filepath.Join(dir, fileName)
			if fileExists(dstName) {
				fmt.Printf("\t\tDest file %s already exists, skipped", dstName)
				continue
			}
		}
		fmt.Printf("\t\tCopy %s to %s\n", originFile, dstName)
		cp := exec.Command("cp", originFile, dstName)
		cp.Start()
		cp.Wait()
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func extractCommit(
	commitHash string,
	buildDir, sDir, oDir, refDir string,
	sFiles, oFiles, refFiles []string,
) {
	gitCheckout := exec.Command("git", "checkout", commitHash)
	gitCheckout.Dir = buildDir
	gitCheckout.Start()
	gitCheckout.Wait()

	renameFiles := make(map[string]string)
	// Rename s file if a single s and a single o does not have a same name
	if len(sFiles) == 1 && len(oFiles) == 1 {
		oName := getFileName(oFiles[0])
		sName := oName + asmsuffix
		sPath := getFilePath(sFiles[0])
		if sPath != "" {
			sName = filepath.Join(sPath, sName)
		}
		if sFiles[0] != sName {
			renameFiles[sFiles[0]] = sName
		}
	}

	// Copy
	copyFilesToDir(buildDir, sFiles, sDir, renameFiles, false, asmsuffix)
	copyFilesToDir(buildDir, oFiles, oDir, renameFiles, false, objsuffix)
	copyFilesToDir(buildDir, refFiles, refDir, renameFiles, true, "")
}

func main() {
	workDir := os.Args[len(os.Args)-1]

	ltFlag := flag.String("l", "x86_64-PC-Linux-GNU-ELF", "the llvm triple for the target binaries")
	singleDirFlag := flag.String("sd", "", "only operate on a single dir")
	printFlag := flag.Bool("print", false, "Print supported llvm triple types for this program")

	flag.Parse()
	llvmTriple := *ltFlag
	singleDir := *singleDirFlag
	printLLVM := *printFlag
	if printLLVM {
		genutils.PrintSupportLlvmTriple(gtutils.LLVMTriples)
		return
	}
	llvmTripleStruct := genutils.ParseLlvmTriple(genutils.CheckLlvmTriple(llvmTriple, gtutils.LLVMTriples))

	osEnvObj := llvmTripleStruct.OS + "-" + llvmTripleStruct.Env + "-" + llvmTripleStruct.Obj
	switch osEnvObj {
	case "Linux-GNU-ELF":
		asmsuffix = ".s"
		objsuffix = ".o"
	case "Win32-MSVC-COFF":
		asmsuffix = ".cod"
		objsuffix = ".obj"
	}

	buildRoot := filepath.Join(workDir, builddir)
	sRoot := filepath.Join(workDir, sdir)
	oRoot := filepath.Join(workDir, odir)
	refRoot := filepath.Join(workDir, refdir)
	os.Mkdir(sRoot, os.ModePerm)
	os.Mkdir(oRoot, os.ModePerm)
	os.Mkdir(refRoot, os.ModePerm)

	var buildDirs []string
	if singleDir != "" {
		buildDirs = []string{singleDir}
	} else {
		buildDirs = genutils.GetDirs(buildRoot)
	}

	for _, dir := range buildDirs {
		buildDir := filepath.Join(buildRoot, dir)
		fmt.Println("In dir " + buildDir)
		sDir := filepath.Join(sRoot, dir)
		oDir := filepath.Join(oRoot, dir)
		refDir := filepath.Join(refRoot, dir)
		os.RemoveAll(sDir)
		os.RemoveAll(oDir)
		os.RemoveAll(refDir)
		_ = os.Mkdir(sDir, os.ModePerm)
		_ = os.Mkdir(oDir, os.ModePerm)
		_ = os.Mkdir(refDir, os.ModePerm)

		ckMaster := exec.Command("git", "checkout", "--hard", "master")
		ckMaster.Dir = buildDir
		ckMaster.Start()
		ckMaster.Wait()

		testStatus := exec.Command("git", "status")
		testStatus.Dir = buildDir
		testStatusOut, err := testStatus.Output()
		if err != nil {
			fmt.Printf("\tExtract Git failed, git status error\n")
			continue
		}
		testStatusStr := string(testStatusOut)
		if !strings.HasPrefix(testStatusStr, "On branch master") {
			fmt.Printf("\tExtract Git failed, should be on branch master, but get status:\n%s",
				testStatusStr)
			continue
		}
		if llvmTripleStruct.Env == "MSVC" {
			// If env is msvc, copy dumpbin out file into ref dir
			dumpbinCpy := exec.Command("bash", "-c",
				strings.Join([]string{"cp",
					filepath.Join(buildDir, "*.dumpbin.out"),
					refDir}, " "))
			dumpbinCpy.Start()
			dumpbinCpy.Wait()
		}
		gitLog := exec.Command("git", "--no-pager", "log")
		gitLog.Dir = buildDir
		gitLogOut, err := gitLog.Output()
		if err != nil {
			fmt.Printf("\tExtract Git failed, git log error\n")
			continue
		}
		lines := bufio.NewScanner(strings.NewReader(string(gitLogOut)))
		var inMessage bool
		var commitHash string
		var sFiles, oFiles, refFiles []string
		for lines.Scan() {
			line := lines.Text()
			if line == "" {
				inMessage = !inMessage
				if !inMessage {
					extractCommit(commitHash,
						buildDir,
						sDir,
						oDir,
						refDir,
						sFiles,
						oFiles,
						refFiles,
					)
				}
				continue
			}
			if !inMessage &&
				strings.HasPrefix(line, "commit ") {
				commitHash = strings.Fields(line)[1]
				fmt.Printf("\tIn Commit: %s\n", commitHash)
				sFiles = make([]string, 0)
				oFiles = make([]string, 0)
				refFiles = make([]string, 0)
				continue
			}
			if inMessage {
				trim := strings.TrimSpace(line)
				// Added or Modified files
				if strings.HasPrefix(trim, "?? ") ||
					strings.HasPrefix(trim, "M ") {
					firstSpace := strings.Index(trim, " ")
					fileName := strings.TrimSpace(trim[firstSpace+1:])
					if strings.HasSuffix(fileName, asmsuffix) {
						sFiles = append(sFiles, fileName)
					} else if strings.HasSuffix(fileName, objsuffix) {
						oFiles = append(oFiles, fileName)
					} else if llvmTripleStruct.Env == "MSVC" && strings.HasSuffix(fileName, ".map") {
						// MSVC generated symbol files: map
						refFiles = append(refFiles, fileName)
					}
				}
			}
		}
		gitCheckout := exec.Command("git", "checkout", "master")
		gitCheckout.Dir = buildDir
		gitCheckout.Start()
		gitCheckout.Wait()
	}
}
