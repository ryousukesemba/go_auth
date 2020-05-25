// sessions.go
package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/bcrypt"
)

//sample2@gmail.com
//password
var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	//秘密鍵の生成
	key = []byte("super-secret-key")
	//秘密鍵を暗号化
	store = sessions.NewCookieStore(key)
)

type User struct {
	Name     string
	Email    string
	Password string
	gorm.Model
}

func connectDB() (*gorm.DB, error) {
	db, err := gorm.Open("sqlite3", "db/user.db")
	if err != nil {
		panic(err)
	}
	db.LogMode(true)
	return db, err
}

func index(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sessionId")
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		fmt.Fprintln(w, "ログイン後です")
	} else {
		//セッションのauthenticatedがfalse(ログインしていない場合)ならエラーを返す
		fmt.Fprintln(w, "ログイン前です")
	}
}
func NewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		//リクエストGETならテンプレートの解析/表示
		tmpl := template.Must(template.ParseFiles("newuser.tmpl"))
		tmpl.Execute(w, "")
	} else if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "フォームの内容にエラーがあります", http.StatusForbidden)
			return
		}
		name := r.Form.Get("name")
		email := r.Form.Get("email")
		pass := r.Form.Get("password")
		hashpass, _ := GenerateHash(pass)

		db, err := connectDB()
		if err != nil {
			http.Error(w, "フォームの内容にエラーがあります", http.StatusForbidden)
			return
		}

		var user User
		user = User{Name: name, Email: email, Password: hashpass}
		db.Create(&user)
	} else {

	}
}
func AllUser(w http.ResponseWriter, r *http.Request) {
	db, _ := connectDB()

	var users []User
	db.Find(&users)

	fmt.Println(users)
}

func ShowUser(w http.ResponseWriter, r *http.Request) {
	currentUser := getCurrentUser(r)
	fmt.Println(currentUser)
	fmt.Println(currentUser.ID)
	fmt.Println(currentUser.Name)
	fmt.Println(currentUser.Email)

	ok := checkLoggedIn(r)
	fmt.Println(ok)
}
func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sessionId")
	// Check if user is authenticated
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		//
		fmt.Fprintln(w, "セッションは保存されています!")
	} else {
		//セッションのauthenticatedがfalse(ログインしていない場合)ならエラーを返す
		http.Error(w, "ログインしてください", http.StatusForbidden)
	}
}

func LoginHangler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sessionId")
	// Authentication goes here
	if r.Method == "GET" {
		//リクエストGETならテンプレートの解析/表示
		tmpl := template.Must(template.ParseFiles("login.tmpl"))
		tmpl.Execute(w, "")
	} else if r.Method == "POST" {
		//リクエストPOSTならフォームの解析/ログイン処理
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "フォームの内容にエラーがあります", http.StatusForbidden)
			return
		}
		email := r.Form.Get("email")
		pass := r.Form.Get("password")
		//データベースと接続
		db, err := connectDB()
		if err != nil {
			http.Error(w, "フォームの内容にエラーがあります", http.StatusForbidden)
			return
		}
		fmt.Println(email)
		fmt.Println(pass)

		//フォームのemailを元にdbからユーザーを検索
		var user User
		if err := db.Where("email = ?", email).Find(&user).Error; err != nil {
			// エラーハンドリング...
			http.Error(w, "emailが違います", http.StatusForbidden)
			return
		}

		//DBハッシュ値とフォームのパスワードがマッチすればnilを返す
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))
		if err != nil {
			http.Error(w, "パスワードが違います", http.StatusForbidden)
			return
		}

		//ユーザーがemailを持っていて、かつ、bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))のerrがなかったら（マッチしていればerrはnil）
		if len(user.Email) > 0 && err == nil {
			// Set user as authenticated
			session.Values["authenticated"] = true
			session.Values["userId"] = user.ID
			session.Save(r, w)
		} else {
			http.Error(w, "エラーです", http.StatusForbidden)
		}
	} else {
		http.Error(w, "予期せぬアクセスです", http.StatusForbidden)
	}

}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sessionId")
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		// Revoke users authentication
		session.Values["authenticated"] = false
		session.Values["userId"] = 0
		session.Save(r, w)
	} else {
		//セッションのauthenticatedがfalse(ログインしていない場合)ならエラーを返す
		http.Error(w, "ログインしてください", http.StatusForbidden)
	}
}

// パスワードハッシュを作る
func GenerateHash(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), err
}

// パスワードがハッシュにマッチするかどうかを調べる
func passwordVerify(hash, pw string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
}

func checkLoggedIn(r *http.Request) bool {
	session, _ := store.Get(r, "sessionId")
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		return true
	} else {
		return false
	}
}

func getCurrentUser(r *http.Request) *User {
	session, _ := store.Get(r, "sessionId")
	var user User
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		sessionUserId := session.Values["userId"]
		db, err := connectDB()
		if err != nil {
			//データベース接続エラー時の処理
		} else {
			//成功したらセッションのユーザーIDを使ってをユーザー取得
			err := db.First(&user, sessionUserId).Error
			if err != nil {
			}
		}
	}
	return &user
}

func main() {
	http.HandleFunc("/secret", secret)
	http.HandleFunc("/users", AllUser)
	http.HandleFunc("/new", NewUser)
	http.HandleFunc("/show", ShowUser)
	http.HandleFunc("/", index)
	http.HandleFunc("/login", LoginHangler)
	http.HandleFunc("/logout", LogoutHandler)

	http.ListenAndServe(":8080", nil)
}
