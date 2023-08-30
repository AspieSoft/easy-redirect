package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AspieSoft/go-regex-re2"
	"github.com/AspieSoft/goutil/v5"
)

var serverDomain string
var domainVerifyPrefix string

var validExtList []string = []string{
	"css",
	"js",
	"less",
	"md",
	"txt",
	"png",
	"jpg",
	"jpeg",
	"gif",
	"mp3",
	"mp4",
	"mov",
	"ogg",
	"wav",
	"webp",
	"webm",
	"weba",
}

var tokenHashKey []byte = goutil.Crypt.RandBytes(64)

var outDir string

var regExt *regexp.Regexp
var regClean *regexp.Regexp

var debugMode bool

var dbRoot string
var dbRedirectsRoot string

func main(){
	file, err := os.ReadFile("./config.json")
	if err != nil {
		panic(err)
	}
	config, err := goutil.JSON.Parse(file)
	if err != nil {
		panic(err)
	}
	serverDomain = goutil.Conv.ToString(config["domain"])
	domainVerifyPrefix = goutil.Conv.ToString(config["verifyPrefix"])

	if stat, err := os.Stat(`./static-site`); err == nil && !stat.IsDir() {
		cmd := exec.Command(`./static-site`)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}

	port := 3000
	for _, arg := range os.Args[1:] {
		if p, err := strconv.Atoi(arg); err == nil && p >= 3000 && p <= 65535 {
			port = p
		}else if arg == "--debug" || arg == "-d" {
			debugMode = true
		}
	}

	outDir, err = filepath.Abs("./dist")
	if err != nil {
		log.Fatal(err)
		return
	}

	dbRoot, err = filepath.Abs("./db/users")
	if err != nil {
		log.Fatal(err)
		return
	}

	dbRedirectsRoot, err = filepath.Abs("./db/redirects")
	if err != nil {
		log.Fatal(err)
		return
	}

	regExt, err = regexp.Compile(`\.[\w_-]+$`)
	if err != nil {
		log.Fatal(err)
		return
	}
	regClean, err = regexp.Compile(`[^\w_\-\/]+`)
	if err != nil {
		log.Fatal(err)
		return
	}

	handlePath()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 102400 {
			size := strconv.Itoa(int(r.ContentLength))
			fmt.Println(errors.New("content length too large: "+size))
			resErr(w, r, 413, "Request Too Large: "+size)
			return
		}

		host := string(regex.Comp(`[^\w_\-\.\:]`).RepStr([]byte(goutil.Clean.Str(r.Host)), []byte{}))
		if host != serverDomain && !regex.Comp(`(localhost|127\.0\.0\.1):[0-9]+`).Match([]byte(host)) {
			// file deepcode ignore OR: false positive
			handleDomainRedirect(w, r, host)
			return
		}

		if !firewall(w, r) {
			return
		}

		url := strings.Trim(goutil.Clean.Str(r.URL.Path), "/")
		if url == "" {
			userEmail := verifyAPI(w, r)
			if userEmail == "" {
				userEmail = handleLogin(w, r)
				if userEmail == "" {
					return
				}
			}

			dbUserRoot, err := goutil.FS.JoinPath(dbRoot, userEmail)
			if err != nil {
				resErr(w, r, 500, "Internal Server Error")
				return
			}

			if stat, err := os.Stat(dbUserRoot); err != nil || !stat.IsDir() {
				if err := os.Mkdir(dbUserRoot, 0755); err != nil {
					resErr(w, r, 500, "Internal Server Error")
					return
				}
			}

			resFile, err := os.ReadFile(filepath.Join(outDir, "index.html"))
			if err != nil {
				resErr(w, r, 404, "Page Not Found")
				return
			}

			domainVerify := domainVerifyPrefix+":"+userEmail
			resFile = regex.Comp(`\{domainVerify\}`).RepStr(resFile, []byte(domainVerify))
			resFile = regex.Comp(`\{domainCNAME\}`).RepStr(resFile, []byte(serverDomain))

			// file deepcode ignore PT: false positive
			if files, err := os.ReadDir(dbUserRoot); err == nil {
				domains := [][]byte{}
				for _, file := range files {
					fileName := regex.Comp(`[^\w_\-\.]`).RepStr([]byte(file.Name()), []byte{})
					domains = append(domains, regex.JoinBytes(
						`<div class="container">`,
						`<a class="domain" href="/`, fileName, '"', '>', fileName, `</a>`,
						`<br/>`,
						`<br/>`,
						`<input type="button" name="remove" value="Remove">`,
						`</div>`,
					))
				}
				resFile = regex.Comp(`\{domains\}`).RepStr(resFile, bytes.Join(domains, []byte(`<br/>`)))
			}else{
				resFile = regex.Comp(`\{domains\}`).RepStr(resFile, []byte{})
			}

			w.Header().Set("content-type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			// file deepcode ignore XSS: false positive
	 		w.Write(resFile)
			return
		}else{
			if handleUrl(w, r, url){
				return
			}

			cUrl := "./"+string(regClean.ReplaceAll(regExt.ReplaceAll([]byte(url), []byte{}), []byte{}))

			for _, ext := range validExtList {
				if strings.HasSuffix(url, "."+ext) {
					if filePath, err := goutil.FS.JoinPath(outDir, cUrl+"."+ext); err == nil {
						if stat, err := os.Stat(filePath); err == nil && !stat.IsDir() {
							http.ServeFile(w, r, filePath)
							return
						}
					}

					resErr(w, r, 404, "page not found")
					return
				}
			}

			if filePath, err := goutil.FS.JoinPath(outDir, cUrl[2:]+".html"); err == nil {
				if stat, err := os.Stat(filePath); err == nil && !stat.IsDir() {
					http.ServeFile(w, r, filePath)
					return
				}
			}

			for _, ext := range validExtList {
				if filePath, err := goutil.FS.JoinPath(outDir, cUrl+"."+ext); err == nil {
					if stat, err := os.Stat(filePath); err == nil && !stat.IsDir() {
						http.ServeFile(w, r, filePath)
						return
					}
				}
			}
		}

		resErr(w, r, 404, "page not found")
	})

	fmt.Println("\x1b[1m\x1b[32mServer Listening On Port\x1b[35m", port, "\x1b[0m")
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
}

func firewall(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength > 102400 {
		size := strconv.Itoa(int(r.ContentLength))
		fmt.Println(errors.New("content length too large: "+size))
		resErr(w, r, 413, "Request Too Large: "+size)
		return false
	}

	host := goutil.Clean.Str(r.Host)
	if host != serverDomain && !regex.Comp(`(localhost|127\.0\.0\.1):[0-9]+`).Match([]byte(host)) {
		fmt.Println(errors.New("invalid host: "+host))
		resErr(w, r, 400, "Invalid Host: "+host)
		return false
	}
	// serverDomain

	method := goutil.Clean.Str(r.Method)
	if !goutil.Contains([]string{"POST", "GET", "HEAD"}, method) {
		fmt.Println(errors.New("invalid method: "+method))
		resErr(w, r, 400, "Invalid Method: "+method)
		return false
	}

	w.Header().Set("Access-Control-Allow-Headers", "Origin,X-Requested-With,content-type,Accept")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,HEAD")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Embedder-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")

	// limit login attempts
	hashedIP := getHashedIP(r)
	if val, ok := failedLogins.Get(hashedIP); ok && val.attempts == 0 {
		resErr(w, r, 429, "Too Many Requests")
		return false
	}

	// rate limit
	if val, ok := rateLimit.Get(hashedIP); ok {
		if val.attempts == 0 {
			resErr(w, r, 429, "Too Many Requests")
			return false
		}else{
			val.attempts--
			rateLimit.Set(hashedIP, val)
		}
	}else{
		rateLimit.Set(hashedIP, failedLogin{
			attempts: 1500, // about 2.5 requests per second
			exp: time.Now().Add(10 * time.Minute).UnixMilli(),
		})
	}

	return true
}

func res(w http.ResponseWriter, r *http.Request, path string){
	fullPath, err := goutil.FS.JoinPath(outDir, path+"/index.html")
	if err != nil {
		resErr(w, r, 404, "Page Not Found")
		return
	}

	if stat, err := os.Stat(fullPath); err == nil && !stat.IsDir() {
		w.WriteHeader(200)
		http.ServeFile(w, r, fullPath)
		return
	}

	fullPath, err = goutil.FS.JoinPath(outDir, path+".html")
	if err != nil {
		resErr(w, r, 404, "Page Not Found")
		return
	}

	if stat, err := os.Stat(fullPath); err == nil && !stat.IsDir() {
		w.WriteHeader(200)
		http.ServeFile(w, r, fullPath)
		return
	}

	resErr(w, r, 404, "Page Not Found")
}

func getFile(path string) []byte {
	fullPath, err := goutil.FS.JoinPath(outDir, path+"/index.html")
	if err != nil {
		return nil
	}

	if file, err := os.ReadFile(fullPath); err == nil {
		return file
	}

	fullPath, err = goutil.FS.JoinPath(outDir, path+".html")
	if err != nil {
		return nil
	}

	if file, err := os.ReadFile(fullPath); err == nil {
		return file
	}

	return nil
}

func resErr(w http.ResponseWriter, r *http.Request, status int, msg string){
	w.WriteHeader(status)

	statusStr := strconv.Itoa(status)
	path := filepath.Join(outDir, "error/error_"+statusStr+"/index.html")

	if stat, err := os.Stat(path); err == nil && !stat.IsDir() {
		http.ServeFile(w, r, path)
		return
	}

	w.Write([]byte("<h1>Error "+statusStr+"</h1><h2>"+msg+"</h2>"))
}

func getPCID(r *http.Request) string {
	res := [][]byte{}

	if hash, err := goutil.Crypt.Hash.New([]byte(goutil.Clean.Str(r.Host)), tokenHashKey); err == nil {
		res = append(res, hash)
	}

	if hash, err := goutil.Crypt.Hash.New([]byte(goutil.Clean.Str(r.Proto)), tokenHashKey); err == nil {
		res = append(res, hash)
	}

	res = append(res, []byte(getHashedIP(r)))

	if hash, err := goutil.Crypt.Hash.New([]byte(goutil.Clean.Str(r.UserAgent())), tokenHashKey); err == nil {
		res = append(res, hash)
	}

	return base64.StdEncoding.EncodeToString(bytes.Join(res, []byte{':'}))
}

func getHashedIP(r *http.Request) string {
	res := [][]byte{}

	if ip := []byte(goutil.Clean.Str(r.Header.Get("X-Real-IP"))); len(ip) != 0 && !regex.Comp(`localhost|127.0.0.1|::1`).Match(ip) {
		if hash, err := goutil.Crypt.Hash.New(ip, tokenHashKey); err == nil {
			res = append(res, hash)
		}
	}else if ip := []byte(goutil.Clean.Str(r.Header.Get("X-Forwarded-For"))); len(ip) != 0 && !regex.Comp(`localhost|127.0.0.1|::1`).Match(ip) {
		if hash, err := goutil.Crypt.Hash.New(ip, tokenHashKey); err == nil {
			res = append(res, hash)
		}
	}

	if ip := []byte(goutil.Clean.Str(r.RemoteAddr)); len(ip) != 0 && !regex.Comp(`localhost|127.0.0.1|::1`).Match(ip) {
		if hash, err := goutil.Crypt.Hash.New(ip, tokenHashKey); err == nil {
			res = append(res, hash)
		}
	}

	return base64.StdEncoding.EncodeToString(bytes.Join(res, []byte{':'}))
}
