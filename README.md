# Casbin Bun Adapter
<p align='left'>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/JunNishimura/casbin-bun-adapter">
  <img alt="GitHub" src="https://img.shields.io/github/license/JunNishimura/casbin-bun-adapter">
  <a href="https://github.com/JunNishimura/casbin-bun-adapter/actions/workflows/test.yml"><img src="https://github.com/JunNishimura/casbin-bun-adapter/actions/workflows/test.yml/badge.svg" alt="test"></a>
  <a href="https://goreportcard.com/report/github.com/JunNishimura/casbin-bun-adapter"><img src="https://goreportcard.com/badge/github.com/JunNishimura/casbin-bun-adapter" alt="Go Report Card"></a>
</p>

## 📖 Overview
casbin-bun-adapter is the [Bun](https://bun.uptrace.dev/) ORM adapter for [Casbin](https://casbin.org/).

## 🙌 Supported DB 
The following databases supported by Bun are also supported by this adapter
1. MySQL
2. PostgreSQL
3. Microsoft SQL Server
4. SQLite

## 💻 Installation 
```
go get github.com/JunNishimura/casbin-bun-adapter
```

## 👀 Example
```go
package main

import (
	casbinbunadapter "github.com/JunNishimura/casbin-bun-adapter"
	"github.com/casbin/casbin/v2"
)

func main() {
	// initialize a Bun adapter and use it in a Casbin enforcer
	a, _ := casbinbunadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/database")
	e, _ := casbin.NewEnforcer("model.conf", a)

	// load the policy from DB.
	_ = e.LoadPolicy()

	// check the permission.
	_, _ = e.Enforce("alice", "data1", "read")

	// modify the policy
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	// e.UpdatePolicy(...)

	// save the policy back to DB.
	_ = e.SavePolicy()
}
```

## 😢 Limitations
casbin-bun-adapter has following limitations.
### 1. Table names cannot be freely specified
To specify the table name in Bun, you need to specify it in a structure tag or call the ModelTableExpr method in the query builder.
```go
type User struct {
  bun.BaseModel `bun:"table:users,alias:u"`
  ID    int64  `bun:"id,pk,autoincrement"`
  Name  string `bun:"name,notnull"`
}
```

```go
res, err := db.NewInsert().
    Model(user).
    ModelTableExpr("custom_name") // specify table name
    Exec(ctx)
```
If you want to create a table with a name specified by the user, you can use ModelTableExpr, but I gave up using ModelTableExpr because I found that query build to tuncate table does not support ModelTableExpr.

If we come up with a better approach, or if Bun's specifications regarding the above change, we will modify this one accordingly.

### 2. Unique indexes cannot be added on columns in the casbin_policies table
For Postgres, you can specify `IF NOT EXISTS` to create a key only when the key does not exist, but other DBs do not support the above syntax by default.

There seems to be no way to check if the index is posted in Bun.

If I find the way to check if the index exists with SQL, it might be possible to achieve this, so I'll leave this as a future issue.

## 🙇‍♂️ Thanks
I would like to express my appreciation to [Gorm Adapter](https://github.com/casbin/gorm-adapter), since casbin-bun-adapter is implemented in a way that fits the Bun ORM based on it.

## 🪧 License
casbin-bun-adapter is released under [MIT License](https://github.com/JunNishimura/casbin-bun-adapter/blob/main/LICENSE).
