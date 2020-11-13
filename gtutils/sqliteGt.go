package utils

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	// For sqlite3 sql plugin init
	_ "github.com/mattn/go-sqlite3"
)

// InsnSupplementary are sparse information for instructions
type InsnSupplementary struct {
	Optional bool
}

// FuncRow stores the information required to create the "func" table
type FuncRow struct {
	Name  string
	Start int
	End   int
}

type funcToInsn struct {
	funcRow FuncRow
	insns   []int
}

// CreateSqliteGt creates an sqlite file "sqlpath" with input insn and func data
func CreateSqliteGt(sqlpath string, insns map[int]InsnSupplementary, funcs map[FuncRow][]int) {
	os.Remove(sqlpath)
	db, err := sql.Open("sqlite3", sqlpath)
	if err != nil {
		fmt.Printf("FATAL: sqlite file %s create failed\n", sqlpath)
		panic(err)
	}
	defer db.Close()

	// create tables
	stm, err := db.Prepare("CREATE TABLE IF NOT EXISTS insn (" +
		"offset INTEGER PRIMARY KEY, " +
		"supplementary TEXT" +
		")")
	if err != nil {
		fmt.Println("FATAL: sqlite statement error")
		panic(err)
	}
	stm.Exec()
	stm.Close()
	stm, err = db.Prepare("CREATE TABLE IF NOT EXISTS func (" +
		"id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"name TEXT, " +
		"start INTEGER, " +
		"end INTEGER" +
		")")
	if err != nil {
		fmt.Println("FATAL: sqlite statement error")
		panic(err)
	}
	stm.Exec()
	stm.Close()
	stm, err = db.Prepare("CREATE TABLE IF NOT EXISTS func2insns (" +
		"id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"fid INTEGER, " +
		"insn INTEGER" +
		")")
	if err != nil {
		fmt.Println("FATAL: sqlite statement error")
		panic(err)
	}
	stm.Exec()
	stm.Close()

	// instructions
	const maxSQLVals = 100
	insertStr := "INSERT INTO insn (offset, supplementary) VALUES "
	value := "(?, ?)"
	insertFormation := make([]string, 0)
	vals := make([]interface{}, 0)
	counter := 0
	for offset, supplementary := range insns {
		if counter++; counter >= maxSQLVals {
			// sqlite3 plugin cannot support too many vals insertion at once
			counter = 0
			insertQuey := insertStr + strings.Join(insertFormation, ",")
			stm, err = db.Prepare(insertQuey)
			if err != nil {
				fmt.Println("FATAL: sqlite insn statement error")
				panic(err)
			}
			_, err = stm.Exec(vals...)
			stm.Close()
			if err != nil {
				fmt.Println("FATAL: sqlite insn value insert error")
				panic(err)
			}
			insertFormation = make([]string, 0)
			vals = make([]interface{}, 0)
		}
		insertFormation = append(insertFormation, value)
		jsonStr := insnSupplementaryToJSON(supplementary)
		vals = append(vals, offset, jsonStr)

	}
	insertStr += strings.Join(insertFormation, ",")
	if len(vals) > 0 {
		stm, err = db.Prepare(insertStr)
		if err != nil {
			fmt.Println("FATAL: sqlite insn statement error")
			panic(err)
		}
		_, err = stm.Exec(vals...)
		stm.Close()
		if err != nil {
			fmt.Println("FATAL: sqlite insn value insert error")
			panic(err)
		}
	}

	funcLst := make([]funcToInsn, 0)
	for funcRow, insns := range funcs {
		sort.Ints(insns)
		funcLst = append(funcLst, funcToInsn{
			funcRow: funcRow,
			insns:   insns,
		})
	}
	sort.Slice(funcLst, func(i, j int) bool {
		return funcLst[i].funcRow.Start < funcLst[j].funcRow.Start
	})

	// functions
	insertStr = "INSERT INTO func (id, name, start, end) VALUES "
	value = "(?, ?, ?, ?)"
	insertFormation = make([]string, 0)
	vals = make([]interface{}, 0)
	counter = 0
	for i, f := range funcLst {
		fr := f.funcRow
		if counter++; counter >= maxSQLVals {
			// sqlite3 plugin cannot support too many vals insertion at once
			counter = 0
			insertQuey := insertStr + strings.Join(insertFormation, ",")
			stm, err = db.Prepare(insertQuey)
			if err != nil {
				fmt.Println("FATAL: sqlite func statement error")
				panic(err)
			}
			_, err = stm.Exec(vals...)
			stm.Close()
			if err != nil {
				fmt.Println("FATAL: sqlite func value insert error")
				panic(err)
			}
			insertFormation = make([]string, 0)
			vals = make([]interface{}, 0)
		}
		insertFormation = append(insertFormation, value)
		vals = append(vals, i, fr.Name, fr.Start, fr.End)
	}
	insertStr += strings.Join(insertFormation, ",")
	if len(vals) > 0 {
		stm, err = db.Prepare(insertStr)
		if err != nil {
			fmt.Println("FATAL: sqlite func statement error")
			panic(err)
		}
		_, err = stm.Exec(vals...)
		if err != nil {
			fmt.Println("FATAL: sqlite func value insert error")
			panic(err)
		}
		stm.Close()
	}

	// func2insns
	insertStr = "INSERT INTO func2insns (fid, insn) VALUES "
	value = "(?, ?)"
	insertFormation = make([]string, 0)
	vals = make([]interface{}, 0)
	counter = 0
	for i, f := range funcLst {
		insns := f.insns
		for _, insn := range insns {
			if counter++; counter >= maxSQLVals {
				// sqlite3 plugin cannot support too many vals insertion at once
				counter = 0
				insertQuey := insertStr + strings.Join(insertFormation, ",")
				stm, err = db.Prepare(insertQuey)
				if err != nil {
					fmt.Println("FATAL: sqlite func2insns statement error")
					panic(err)
				}
				_, err = stm.Exec(vals...)
				stm.Close()
				if err != nil {
					fmt.Println("FATAL: sqlite func2insns value insert error")
					panic(err)
				}
				insertFormation = make([]string, 0)
				vals = make([]interface{}, 0)
			}
			insertFormation = append(insertFormation, value)
			vals = append(vals, i, insn)
		}
	}
	insertStr += strings.Join(insertFormation, ",")
	if len(vals) > 0 {
		stm, err = db.Prepare(insertStr)
		if err != nil {
			fmt.Println("FATAL: sqlite func statement error")
			panic(err)
		}
		_, err = stm.Exec(vals...)
		if err != nil {
			fmt.Println("FATAL: sqlite func value insert error")
			panic(err)
		}
		stm.Close()
	}
}

// ReadSqliteGt read an sqlite file "sqlpath" for output insn and func data
func ReadSqliteGt(sqlpath string) (insns map[int]InsnSupplementary, funcs map[FuncRow]bool) {
	insns = make(map[int]InsnSupplementary)
	funcs = make(map[FuncRow]bool)
	db, err := sql.Open("sqlite3", sqlpath)
	if err != nil {
		fmt.Printf("FATAL: sqlite file %s open failed\n", sqlpath)
		panic(err)
	}

	const maxSQLQuery = 50000
	// instructions
	sum, err := db.Query("SELECT COUNT(*) FROM insn")
	if err != nil {
		fmt.Println("FATAL: sqlite selection count from insn failed")
	}
	var count int
	sum.Next()
	sum.Scan(&count)
	sum.Close()

	for i := 0; i < count; i += maxSQLQuery {
		rows, err := db.Query("SELECT offset, supplementary FROM insn LIMIT " +
			strconv.Itoa(maxSQLQuery) + " OFFSET " + strconv.Itoa(i))
		if err != nil {
			fmt.Println("FATAL: sqlite select from insn failed")
			panic(err)
		}
		var offset int
		var jsonStr string
		for rows.Next() {
			rows.Scan(&offset, &jsonStr)
			insns[offset] = jsonToInsnSupplementary(jsonStr)
		}
		rows.Close()
	}

	// functions
	sum, err = db.Query("SELECT COUNT(*) FROM func")
	if err != nil {
		fmt.Println("FATAL: sqlite selection count from func failed")
	}
	sum.Next()
	sum.Scan(&count)
	sum.Close()

	for i := 0; i < count; i += maxSQLQuery {
		rows, err := db.Query("SELECT name, start, end FROM func LIMIT " +
			strconv.Itoa(maxSQLQuery) + " OFFSET " + strconv.Itoa(i))
		if err != nil {
			fmt.Println("FATAL: sqlite select from func failed")
			panic(err)
		}
		var name string
		var fStart, fEnd int
		for rows.Next() {
			rows.Scan(&name, &fStart, &fEnd)
			funcs[FuncRow{Name: name, Start: fStart, End: fEnd}] = true
		}
		rows.Close()
	}
	return
}

// ReadSqliteGtFuncInOrder read an sqlite file "sqlpath" for output func data
// output is in the form of a list ordered by start of func field
func ReadSqliteGtFuncInOrder(sqlpath string) (funcs []FuncRow) {
	funcs = make([]FuncRow, 0)
	db, err := sql.Open("sqlite3", sqlpath)
	if err != nil {
		fmt.Printf("FATAL: sqlite file %s open failed\n", sqlpath)
		panic(err)
	}

	const maxSQLQuery = 50000
	// functions
	sum, err := db.Query("SELECT COUNT(*) FROM func")
	if err != nil {
		fmt.Println("FATAL: sqlite selection count from func failed")
	}
	var count int
	sum.Next()
	sum.Scan(&count)
	sum.Close()

	for i := 0; i < count; i += maxSQLQuery {
		rows, err := db.Query("SELECT name, start, end FROM func ORDER BY start LIMIT " +
			strconv.Itoa(maxSQLQuery) + " OFFSET " + strconv.Itoa(i))
		if err != nil {
			fmt.Println("FATAL: sqlite select from func failed")
			panic(err)
		}
		var name string
		var fStart, fEnd int
		for rows.Next() {
			rows.Scan(&name, &fStart, &fEnd)
			funcs = append(funcs, FuncRow{Name: name, Start: fStart, End: fEnd})
		}
		rows.Close()
	}
	return
}

func insnSupplementaryToJSON(supplementary InsnSupplementary) (jsonStr string) {
	if supplementary.Optional == false {
		// no need to put supplementary data
		return
	}
	jsonBytes, _ := json.Marshal(supplementary)
	jsonStr = string(jsonBytes)
	return
}

func jsonToInsnSupplementary(jsonStr string) (supplementary InsnSupplementary) {
	if jsonStr == "" {
		return
	}
	json.Unmarshal([]byte(jsonStr), &supplementary)
	return
}
