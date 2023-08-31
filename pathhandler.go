package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AspieSoft/go-regex-re2"
	"github.com/AspieSoft/gomail"
	"github.com/AspieSoft/goutil/v5"
	"github.com/alphadose/haxmap"
)

type authToken struct {
	email string
	token string
	exp int64
	verified bool
}

type failedLogin struct {
	attempts int
	exp int64
}

var authTokens *haxmap.Map[string, authToken] = haxmap.New[string, authToken]()
var failedLogins *haxmap.Map[string, failedLogin] = haxmap.New[string, failedLogin]()
var rateLimit *haxmap.Map[string, failedLogin] = haxmap.New[string, failedLogin]()

var loginFailTime time.Duration = 12 * time.Hour
var loginFailLimit int = 3

var mailer gomail.Mailer

func init(){
	// setup email server

	file, err := os.ReadFile("./email.json")
	if err != nil {
		panic(err)
	}
	config, err := goutil.JSON.Parse(file)
	if err != nil {
		panic(err)
	}
	mailer, err = gomail.NewMailer(
		goutil.Conv.ToString(config["email"]), // a real email address
		goutil.Conv.ToString(config["passwd"]), // email password or an app password
		gomail.HOST.Gmail, // an email host
		goutil.Conv.ToString(config["name"]), // (optional) Custom Name to send emails as by default
		// Note: A custom name Must be a valid alias in gmail or may be required with your host of choice
	)
	if err != nil {
		panic(err)
	}

	go func(){
		for {
			time.Sleep(10 * time.Minute)

			now := time.Now().UnixMilli()

			authTokens.ForEach(func(key string, val authToken) bool {
				if now > val.exp {
					authTokens.Del(key)
				}
				return true
			})

			failedLogins.ForEach(func(key string, val failedLogin) bool {
				if now > val.exp {
					authTokens.Del(key)
				}
				return true
			})

			rateLimit.ForEach(func(key string, val failedLogin) bool {
				if now > val.exp {
					authTokens.Del(key)
				}
				return true
			})
		}
	}()
}

func handlePath(){
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if !firewall(w, r) {
			return
		}

		userEmail := verifyAPI(w, r)
		pcID := getPCID(r)

		http.SetCookie(w, &http.Cookie{
			Name: "auth-token",
			Value: "",
			Expires: time.Now(),
			Secure: true,
			HttpOnly: true,
		})

		w.WriteHeader(204)
		w.Write([]byte{})

		if userEmail == "" {
			return
		}

		authTokens.Del(pcID)
	})

	http.HandleFunc("/save-domain-list", func(w http.ResponseWriter, r *http.Request) {
		if !firewall(w, r) {
			return
		}

		hashedIP := getHashedIP(r)
		if val, ok := failedLogins.Get(hashedIP); ok && val.attempts == 0 {
			w.WriteHeader(429)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Too Many Requests"}`))
			return
		}

		userEmail := verifyAPI(w, r)
		if userEmail == "" {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		body, err := goutil.JSON.Decode(r.Body)
		if err != nil {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		body = goutil.Clean.JSON(body).(map[string]interface{})

		var list map[string]interface{}
		var hasList bool
		if val, ok := body["list"]; ok {
			hasList = true
			list = goutil.ToType[map[string]interface{}](val)
		}

		if !hasList {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		dbUserRoot, err := goutil.FS.JoinPath(dbRoot, userEmail)
		if err != nil {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		// get list of current uri files
		fileList := map[string]bool{}
		if files, err := os.ReadDir(dbUserRoot); err == nil {
			for _, file := range files {
				if file.IsDir() {
					fileList[string(regex.Comp(`[^\w_\-\.]`).RepStr([]byte(file.Name()), []byte{}))] = true
				}
			}
		}

		domainVerify := domainVerifyPrefix+":"+userEmail

		failList := []string{}

		// add uri list to files
		for _, val := range list {
			domain := string(regex.Comp(`[^\w_\-\.]`).RepStr(goutil.Conv.ToBytes(val), []byte{}))
			if domain != "" {
				delete(fileList, domain)
				if path, err := goutil.FS.JoinPath(dbUserRoot, domain); err == nil {
					// verify domain ownership
					valid := false
					if txtList, err := net.LookupTXT("verify_redirect."+domain); err == nil {
						for _, txt := range txtList {
							if txt == domainVerify {
								valid = true
								os.Mkdir(path, 0755)
								os.WriteFile(path+"/domain.key", []byte(domainVerify), 0644)
								break
							}
						}
					}

					if !valid {
						failList = append(failList, domain)
					}
				}
			}
		}

		// remove old uri files
		for name, val := range fileList {
			if val && name != "" && name != "." && name != ".." {
				if path, err := goutil.FS.JoinPath(dbUserRoot, name); err == nil {
					os.RemoveAll(path)
				}
			}
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")

		if json, err := goutil.JSON.Stringify(map[string]interface{}{
			"success": true,
			"failList": failList,
			"hasFailList": len(failList) != 0,
		}); err == nil {
			w.Write(json)
		}else if len(failList) != 0 {
			w.Write([]byte(`{"success": true, "hasFailList": true}`))
		}else{
			w.Write([]byte(`{"success": true}`))
		}
	})

	http.HandleFunc("/save-redirect-list", func(w http.ResponseWriter, r *http.Request) {
		if !firewall(w, r) {
			return
		}

		hashedIP := getHashedIP(r)
		if val, ok := failedLogins.Get(hashedIP); ok && val.attempts == 0 {
			w.WriteHeader(429)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Too Many Requests"}`))
			return
		}

		userEmail := verifyAPI(w, r)
		if userEmail == "" {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		body, err := goutil.JSON.Decode(r.Body)
		if err != nil {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		body = goutil.Clean.JSON(body).(map[string]interface{})

		var domain string
		var list map[string]interface{}
		var hasList bool
		if val, ok := body["domain"]; ok {
			domain = goutil.Conv.ToString(val)
		}

		if val, ok := body["list"]; ok {
			hasList = true
			list = goutil.ToType[map[string]interface{}](val)
		}

		domain = string(regex.Comp(`[^\w_\-\.]`).RepStr([]byte(domain), []byte{}))

		if domain == "" || !hasList {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		dbDomainRoot, err := goutil.FS.JoinPath(dbRoot, userEmail, domain)
		if err != nil {
			w.WriteHeader(400)
			w.Header().Set("content-type", "application/json")
			w.Write([]byte(`{"error": "Bad Request"}`))
			return
		}

		// get list of current uri files
		fileList := map[string]bool{}
		if files, err := os.ReadDir(dbDomainRoot); err == nil {
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".url") {
					fileList[string(regex.Comp(`[^\w_\-\.]`).RepStr([]byte(file.Name()), []byte{}))] = true
				}
			}
		}

		domainVerify := domainVerifyPrefix+":"+userEmail

		// add uri list to files
		for _, redirect := range list {
			if red, ok := redirect.(map[string]interface{}); ok {
				var sub string
				var uri []byte
				if val, ok := red["subdomain"]; ok {
					sub = string(regex.Comp(`[^\w_\-\.]`).RepStr(goutil.Conv.ToBytes(val), []byte{})) + ".url"
				}
				if val, ok := red["uri"]; ok {
					uri = goutil.Conv.ToBytes(val)
				}
				if val, ok := red["status"]; ok {
					status := goutil.Conv.ToBytes(val)
					if bytes.Equal(status, []byte("301")) || bytes.Equal(status, []byte("302")) {
						uri = append(uri, '\n')
						uri = append(uri, goutil.Conv.ToBytes(val)...)
					}
				}

				if sub != "" && len(uri) != 0 {
					delete(fileList, sub)

					// verify domain ownership
					if txt, err := os.ReadFile(dbDomainRoot+"/domain.key"); err == nil && string(txt) == domainVerify {
						if path, err := goutil.FS.JoinPath(dbDomainRoot, sub); err == nil {
							os.WriteFile(path, uri, 0644)
							if rPath, err := goutil.FS.JoinPath(dbRedirectsRoot, string(regex.Comp(`\.[\w_\-]+$`).RepStr([]byte(sub), []byte{'.'}))+domain); err == nil {
								os.Link(path, rPath)
							}
						}
					}
				}
			}
		}

		// remove old uri files
		for name, val := range fileList {
			if val && name != "" && name != "." && name != ".." {
				if path, err := goutil.FS.JoinPath(dbDomainRoot, name); err == nil {
					// verify domain ownership
					if txt, err := os.ReadFile(dbDomainRoot+"/domain.key"); err == nil && string(txt) == domainVerify {
						os.Remove(path)
						if rPath, err := goutil.FS.JoinPath(dbRedirectsRoot, string(regex.Comp(`\.[\w_\-]+$`).RepStr([]byte(name), []byte{'.'}))+domain); err == nil {
							os.Remove(rPath)
						}
					}
				}
			}
		}

		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"success": true}`))
	})
}

func handleUrl(w http.ResponseWriter, r *http.Request, url string) bool {
	userEmail := verifyAPI(w, r)

	domain := regex.Comp(`[^\w_\-\.]`).RepStr([]byte(url), []byte{})

	dbDomainRoot, err := goutil.FS.JoinPath(dbRoot, userEmail, string(domain))
	if err != nil {
		return false
	}

	// file deepcode ignore PT: false positive
 	if files, err := os.ReadDir(dbDomainRoot); err == nil {
		resFile := getFile("domain")
		if resFile == nil {
			resErr(w, r, 404, "page not found")
			return true
		}

		resFile = regex.Comp(`\{domain\}`).RepStr(resFile, []byte(url))
		resFile = regex.Comp(`\{domainCNAME\}`).RepStr(resFile, []byte(serverDomain))

		redirectList := [][]byte{}
		for _, file := range files {
			fileName := regex.Comp(`([^\w_\-\.]|\.[\w_\-]+$)`).RepStr([]byte(file.Name()), []byte{})

			if path, err := goutil.FS.JoinPath(dbDomainRoot, string(fileName)+".url"); err == nil {
				uri, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				uriData := bytes.SplitN(uri, []byte{'\n'}, 2)
				if len(uriData) == 0 {
					continue
				}

				perm := ``
				if len(uriData) > 1 && bytes.Equal(uriData[1], []byte("301")) {
					perm = ` checked`
				}

				randCheckID := `checkbox_`+string(goutil.Crypt.RandBytes(8, []byte("-_")))

				redirectList = append(redirectList, regex.JoinBytes(
					`<div class="container">`,
					`Subdomain:<input type="text" name="subdomain" value="`, fileName, `" placeholder="subdomain"/>`,
					`.`, domain,
					`<br/>`,
					`Redirect:<input type="text" name="redirect" value="`, uriData[0], `" placeholder="redirect"/>`,
					`<br/>`,
					`<input type="checkbox" id="`, randCheckID, `" name="permanent"`, perm, `/><label for="`, randCheckID, `" class="checkbox">Permanent</label>`,
					`<br/>`,
					`<input type="button" name="remove" value="Remove">`,
					`</div>`,
				))
			}
		}
		resFile = regex.Comp(`\{redirects\}`).RepStr(resFile, bytes.Join(redirectList, []byte{'\n'}))

		w.Header().Set("content-type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		w.Write(resFile)
		return true
	}

	return false
}

func handleLogin(w http.ResponseWriter, r *http.Request) string {
	r.ParseForm()

	email := r.PostFormValue("email")
	if email == "" {
		res(w, r, "login")
		return ""
	}

	email = goutil.Clean.Str(email)
	email = string(regex.Comp(`[^\w_\-@.+]`).RepStr([]byte(email), []byte{}))
	if email == "" {
		resErr(w, r, 400, "Bad Request")
		return ""
	}

	if !regex.Comp(emailMatch).Match([]byte(email)) {
		resErr(w, r, 403, "Permission Denied")
		return ""
	}

	pcID := getPCID(r)
	hashedIP := getHashedIP(r)

	if val, ok := failedLogins.Get(hashedIP); ok && val.attempts == 0 {
		resErr(w, r, 429, "Too Many Requests")
		return ""
	}

	authCode := r.PostFormValue("auth-code")
	if authCode != "" {
		authCode = goutil.Clean.Str(authCode)
		authCode = string(regex.Comp(`[^\w_\-]`).RepStr([]byte(authCode), []byte{}))
		if authCode == "" {
			resErr(w, r, 400, "Bad Request")
			return ""
		}

		// verify auth code
		auth, ok := authTokens.Get(pcID)
		if !ok || auth.verified {
			resErr(w, r, 400, "Bad Request")
			return ""
		}

		if auth.email != email || auth.token != authCode {
			if val, ok := failedLogins.Get(hashedIP); ok {
				val.attempts--
				val.exp = time.Now().Add(loginFailTime).UnixMilli()
				failedLogins.Set(hashedIP, val)
			}else{
				failedLogins.Set(hashedIP, failedLogin{
					attempts: loginFailLimit,
					exp: time.Now().Add(loginFailTime).UnixMilli(),
				})
			}

			resErr(w, r, 400, "Bad Request")
			return ""
		}

		token := string(goutil.Crypt.RandBytes(256))
		exp := time.Now().Add(24 * time.Hour)

		authTokens.Set(pcID, authToken{
			email: email,
			token: token,
			exp: exp.UnixMilli(),
			verified: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name: "auth-token",
			Value: token,
			Expires: exp,
			Secure: true,
			HttpOnly: true,
		})

		hash := sha256.Sum256([]byte(auth.email))
		return string(regex.Comp(`[^\w_\-]`).RepStr([]byte(base64.StdEncoding.EncodeToString(hash[:])), []byte("--")))
	}


	file := getFile("verify")
	if file == nil {
		resErr(w, r, 500, "missing login file")
		return ""
	}

	file = regex.Comp(`\{email\}`).RepStr(file, []byte(email))

	code := string(goutil.Crypt.RandBytes(12))
	authTokens.Set(pcID, authToken{
		email: email,
		token: code,
		exp: time.Now().Add(10 * time.Minute).UnixMilli(),
		verified: false,
	})

	if debugMode {
		// in debug mode, auto fill input and skip the email
		file = regex.Comp(`\{DebugAuthCode\}`).RepStr(file, []byte(code))
	}else{
		// send email with auth code
		mailer.Send([]string{email}, "Auth Code", "Email: "+email+"<br>Auth Code: "+code, gomail.MIME.Html)
		file = regex.Comp(`\{DebugAuthCode\}`).RepStr(file, []byte{})
	}

	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	// file deepcode ignore XSS: Already Sanitized
	w.Write(file)

	return ""
}

func verifyAPI(w http.ResponseWriter, r *http.Request) string {
	if debugMode {
		return "localhost"
	}

	cookie, err := r.Cookie("auth-token")
	if err != nil || cookie.Value == "" {
		return ""
	}

	pcID := getPCID(r)
	hashedIP := getHashedIP(r)

	if val, ok := failedLogins.Get(hashedIP); ok && val.attempts == 0 {
		resErr(w, r, 429, "Too Many Requests")
		return ""
	}

	auth, ok := authTokens.Get(pcID)
	if !ok || !auth.verified || auth.token != cookie.Value {
		return ""
	}

	hash := sha256.Sum256([]byte(auth.email))
	return string(regex.Comp(`[^\w_\-]`).RepStr([]byte(base64.StdEncoding.EncodeToString(hash[:])), []byte("--")))
}

func handleDomainRedirect(w http.ResponseWriter, r *http.Request, domain string){
	if path, err := goutil.FS.JoinPath(dbRedirectsRoot, domain); err == nil {
		if uri, err := os.ReadFile(path); err == nil && len(uri) != 0 {
			if bytes.HasPrefix(uri, []byte("/")) {
				uri = append([]byte("https://"+domain), uri...)
			}

			uriData := bytes.SplitN(uri, []byte{'\n'}, 2)
			if len(uriData) == 0 {
				resErr(w, r, 400, "Bad Request")
				return
			}

			// prevent self redirects
			if !regex.Comp(`https?://`).Match(uriData[0]) || regex.Comp(`^(https?://|)%1`, serverDomain).Match(uriData[0]) || regex.Comp(`^(https?://|)(%1|)%2`, goutil.Clean.Str(r.Host), goutil.Clean.Str(r.RequestURI)).Match(uriData[0]) {
				resErr(w, r, 400, "Bad Request")
				return
			}

			status := 302
			if len(uriData) > 1 && bytes.Equal(uriData[1], []byte("301")) {
				status = 301
			}

			http.Redirect(w, r, string(uriData[0]), status)
			return
		}
	}

	resErr(w, r, 404, "Redirect Not Found")
}
