package elfutils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	gtutils "github.com/pangine/disasm-gt-generator/gtutils"
)

// GenSymbol generate symbol using input binary fin into fout symbol file
func GenSymbol(fin string, fout string, gnuPrefix bool) (r string) {
	NmCmd := "nm"
	if gnuPrefix {
		NmCmd = "gnm"
	}
	nm := exec.Command(NmCmd, "-f", "sys5", "--numeric-sort", "--defined-only", "--line-numbers", fin)
	res, errin := nm.Output()
	if errin != nil {
		fmt.Println(nm.Args)
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

// SymbolResolve resolves input symbol string
func SymbolResolve(symbols string) (fmap []gtutils.SymbolFuncInfo) {
	fmap = make([]gtutils.SymbolFuncInfo, 0)
	lines := bufio.NewScanner(strings.NewReader(symbols))
	for lines.Scan() {
		fields := strings.Split(lines.Text(), "|")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if len(fields) != 7 {
			continue
		}
		if strings.ToLower(fields[3]) != "func" {
			continue
		}
		off64, _ := strconv.ParseUint(fields[1], 16, 64)
		off := int(off64)
		size64, _ := strconv.ParseUint(fields[4], 16, 64)
		size := int(size64)
		fName := fields[0]
		secTab := strings.Index(fields[6], "\t")
		if secTab < 0 {
			fmap = append(fmap, gtutils.SymbolFuncInfo{
				Function:   fName,
				HaveSource: false,
				Source:     "",
				Offset:     int(off),
				Size:       size,
				Line:       0,
				Section:    fields[6]})
		} else {
			secTabSeqLast := secTab
			for ; fields[6][secTabSeqLast] == '\t'; secTabSeqLast++ {
			}
			secName := fields[6][:secTab]
			srcFile := fields[6][secTabSeqLast:]
			fSrc, line := findSrcFile(srcFile)
			fmap = append(fmap, gtutils.SymbolFuncInfo{
				Function:   fName,
				HaveSource: true,
				Source:     fSrc,
				Offset:     int(off),
				Size:       size,
				Line:       line,
				Section:    secName})
		}
	}
	return
}

func findSrcFile(fsrc string) (file string, line int) {
	lastcolon := strings.LastIndex(fsrc, ":")
	if lastcolon == -1 {
		lastcolon = len(fsrc)
	} else {
		line64, err := strconv.ParseInt(fsrc[lastcolon+1:], 10, 64)
		if err == nil {
			line = int(line64)
		}
	}
	file = fsrc[:lastcolon]
	return
}
