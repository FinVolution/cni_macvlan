package db

import (
	"database/sql"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/config"
	. "github.com/containernetworking/plugins/plugins/main/macvlan/macvlanlog"
	"strconv"

	//"// fmt"
	"github.com/containernetworking/plugins/plugins/main/macvlan/stringutils"
	_ "github.com/go-sql-driver/mysql"
	"io/ioutil"
)

func GetDBConnStr() string {
	dat, err := ioutil.ReadFile(stringutils.CleanString(DBConfigFile))
	if err != nil {
		return ""
	}
	conn := string(dat)
	conn = stringutils.CleanString(conn)
	return conn
}

func DBConnect() *sql.DB {
	DebugLog.Println("conn :", GetDBConnStr())
	db, err := sql.Open("mysql", GetDBConnStr() /*"root:dzz@tcp(127.0.0.1:3306)/ipamdemo" */)
	if err != nil {
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}
	//defer db.Close()

	// Open doesn't open a connection. Validate DSN data:
	err = db.Ping()
	DebugLog.Println("db ping :", err)
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	// fmt.Println("ok")
	return db
}

func GetIp(db *sql.DB, podname string) (err error, rdid int, ip string, active int) {
	//db.Exec("select podname, ip from ip where podname = '%s'", podname)
	var (
		id         int
		podname_db string
		ip_db      string
		isactive   int
	)
	//podname = "aaa"
	// fmt.Println(podname)
	sql := "select id, pod_name, ip, isactive from ip where isactive = 1 and pod_name ='" + podname + "' order by id desc limit 1"
	DebugLog.Println("db sql :", sql)
	rows, err := db.Query(sql)
	checkErr(err)
	DebugLog.Println("db.Query  :", err)
	if err != nil {
		return err, 0, "", isactive
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&id, &podname_db, &ip_db, &isactive)
		//if err != nil {
		//	log.Fatal(err)
		//}
		if err != nil {
			DebugLog.Println("rows.Scan: ", err)
			return err, 0, "", 0
		}
		DebugLog.Println("id:", id, " pod_name: ", podname_db, " ip: ", ip_db)
	}
	err = rows.Err()
	checkErr(err)

	if err != nil {
		return err, 0, "", isactive
	}
	rdid = id
	return nil, rdid, ip_db, isactive
}

func checkErr(err error) {
	//if err != nil {
	//	log.Fatal(err)
	//}
}
func UpdatePod(db *sql.DB, podname string, rdid int, ip string, isactive int) error {
	sql := "UPDATE ip SET isactive = " + strconv.Itoa(isactive) + " WHERE id =? "
	DebugLog.Println(" UpdatePod sql: ", sql, db)
	stmt, err := db.Prepare(sql)
	checkErr(err)
	DebugLog.Println(" db.Prepare: ", err)
	if err != nil {
		return err
	}
	res, err := stmt.Exec(rdid)
	checkErr(err)
	DebugLog.Println(" stmt.Exec: ", rdid, err)
	if err != nil {
		return err
	}
	num, err := res.RowsAffected()

	checkErr(err)
	// fmt.Println(num)
	if err != nil {
		return err
	}
	DebugLog.Println(" res.RowsAffected: ", num, err)
	if num == 0 {
		return nil
	}
	return nil
}
