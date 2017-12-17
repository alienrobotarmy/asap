package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"regexp"
	"strings"
)

/*
Built:
'.*Built (inbound|outbound) (TCP|UDP) connection ([0-9]*) for ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*)\ .*\ to ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*)\ '
[0] = Match
[1] = Direction
[2] = Proto
[3] = ID
[4] = SRC IF
[5] = SRC IP
[6] = SRC Port
[7] = DST IF
[8] = DST IP
[9] = DST Port



*/

var needs_commit int

func db_begin(db *sql.DB) {
	if db != nil {
		_, err := db.Exec("BEGIN")
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: %q\n", err)
		} else {
			needs_commit = 1
		}
	}
}
func db_commit(db *sql.DB) {
	if db != nil {
		if needs_commit == 1 {
			_, err := db.Exec("COMMIT")
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: %q\n", err)
			} else {
				needs_commit = 0
			}
		}
	}
}
func parse_deny(db *sql.DB, match []string) {
	if db != nil {
		var sqlQuery string
		sqlQuery = fmt.Sprintf("insert into stats values(0, 'deny', 'deny', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '', '', '')", match[1], strings.ToLower(match[2]), match[4], match[5], match[6], match[8], match[9], match[10])
		_, err := db.Exec(sqlQuery)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%q: %s\n", err, sqlQuery)
		}
	} else {
		fmt.Printf("xx [DENY] %s %s:%s/%s [%s] %s:%s/%s\n", match[1], match[4], match[5], match[6], strings.ToLower(match[2]), match[8], match[9], match[10])
	}
}
func parse_tear(db *sql.DB, match []string) {
	if db != nil {
		var sqlQuery string
		sqlQuery = fmt.Sprintf("update stats set bytes = \"%s\" where session_id = \"%s\"", match[11], match[3])
		_, err := db.Exec(sqlQuery)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%q: %s\n", err, sqlQuery)
		}
	} else {
		fmt.Printf(".. [%s] %s %s:%s/%s [%s] %s:%s/%s [%s] %s\n", match[3], match[1], match[4], match[5], match[6], strings.ToLower(match[2]), match[7], match[8], match[9], match[10], match[11])
	}
}
func parse_build(db *sql.DB, match []string) {
	if db != nil {
		var sqlQuery string
		if match[2] == "inbound" {
			sqlQuery = fmt.Sprintf("insert into stats values('%s', 'inbound', 'allow', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '', '', '')", match[4], match[1], strings.ToLower(match[3]), match[5], match[6], match[7], match[8], match[9], match[10])
		} else {
			sqlQuery = fmt.Sprintf("insert into stats values('%s', 'outbound', 'allow', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '', '', '')", match[4], match[1], strings.ToLower(match[3]), match[8], match[9], match[10], match[5], match[6], match[7])
		}
		_, err := db.Exec(sqlQuery)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%q: %s\n", err, sqlQuery)
		}
	} else {
		if match[2] == "inbound" {
			fmt.Printf("<- [%s] %s %s/%s [%s] %s/%s\n", match[4], match[1], match[6], match[7], strings.ToLower(match[3]), match[9], match[10])
		} else {
			fmt.Printf("-> [%s] %s %s/%s [%s] %s/%s\n", match[4], match[1], match[9], match[10], strings.ToLower(match[3]), match[6], match[7])
		}
	}
}
func helpMesg() {
	fmt.Printf("ASAParser: Copyleft (l) 2016 Jess Mahan\n")
	fmt.Printf("This program helps decipher crappy ASA logs\n\n")
	fmt.Printf("There are two modes to this program:\n")
	fmt.Printf(" 1) Print readable ASCII to the terminal\n\tcat asaLog.txt | asap\nor\n")
	fmt.Printf(" 2) Convert the ASA Log into an SQLite DB\n\tcat asaLog.txt | asap -o sqlite.db\n")
}

func main() {
	outPut := flag.String("o", "", "SQLite output")
	qBuf := flag.Int("b", 1024, "SQLite commit buffer")
	help := flag.Bool("h", false, "Help")
	flag.Parse()

	if *help == true {
		helpMesg()
		os.Exit(0)
	}

	var db *sql.DB
	var i int
	var err error

	//db := new(sql.DB)

	if len(*outPut) > 0 {
		db, err = sql.Open("sqlite3", *outPut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sql.Open: %v\n", err)
		}
		//defer db.Close()
		sqlQuery := `create table stats (session_id integer,
		    direction text,
		    allowed integer,
		    date text,
		    protocol text,
		    src_if text,
		    src_ip text,
		    src_port integer,
		    dst_if text,
		    dst_ip text,
		    dst_port integer,
		    bytes integer,
		    duration text,
		    access_group)
		    `
		_, err = db.Exec(sqlQuery)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "%q: %s\n", err, sqlQuery)
			fmt.Fprintf(os.Stderr, "WARN: %q\n", err)
		}
	}
	//	fmt.Printf("[%q]\n", db)

	regBuildString := "([A-Za-z]{3}[ ]*[0-9]{1,2} ..:..:.. ).*Built (inbound|outbound) (TCP|UDP) connection ([0-9]*) for ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*)\\ .*\\ to ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*)\\ "
	regDenyString := "([A-Za-z]{3}[ ]*[0-9]{1,2} ..:..:.. ).*Deny (.*) (src|dst) ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*) (src|dst) ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*) "
	regTearString := "([A-Za-z]{3}[ ]*[0-9]{1,2} ..:..:.. ).*Teardown (TCP|UDP) connection ([0-9]*) for ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*) to ([a-zA-Z0-9]*):([0-9.]*)/([0-9]*) duration ([0-9:]*) bytes ([0-9]*) .*"

	scanner := bufio.NewScanner(os.Stdin)
	regBuild := regexp.MustCompilePOSIX(regBuildString)
	regDeny := regexp.MustCompilePOSIX(regDenyString)
	regTear := regexp.MustCompilePOSIX(regTearString)

	db_begin(db)
	for i = 0; scanner.Scan(); i++ {
		line := scanner.Text()
		match := regBuild.FindStringSubmatch(line)
		if match != nil {
			parse_build(db, match)
		}
		match = regDeny.FindStringSubmatch(line)
		if match != nil {
			parse_deny(db, match)
		}
		match = regTear.FindStringSubmatch(line)
		if match != nil {
			parse_tear(db, match)
		}
		if i >= *qBuf {
			db_commit(db)
			db_begin(db)
			i = 0
		}
	}
	db_commit(db)
}
