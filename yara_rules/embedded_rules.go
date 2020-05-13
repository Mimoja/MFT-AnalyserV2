// Code generated by fileb0x at "2020-05-13 14:37:22.574916424 +0200 CEST m=+0.000909020" from config file "embedding_rules.yaml" DO NOT EDIT.
// modification hash(76bdfc8b947f0d76ddff59f3a0e3ce6e.c422aa8db5dbf514f930c246e37af8db)

package yara_rules


import (
  "bytes"
  
  "context"
  "io"
  "net/http"
  "os"
  "path"


  "golang.org/x/net/webdav"


)

var ( 
  // CTX is a context for webdav vfs
  CTX = context.Background()

  
  // FS is a virtual memory file system
  FS = webdav.NewMemFS()
  

  // Handler is used to server files through a http handler
  Handler *webdav.Handler

  // HTTP is the http file system
  HTTP http.FileSystem = new(HTTPFS)
)

// HTTPFS implements http.FileSystem
type HTTPFS struct {
	// Prefix allows to limit the path of all requests. F.e. a prefix "css" would allow only calls to /css/*
	Prefix string
}



// FileYaraRulesAmdYara is "yara_rules/amd.yara"
var FileYaraRulesAmdYara = []byte("\x72\x75\x6c\x65\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x52\x4b\x5f\x41\x4e\x44\x5f\x41\x53\x4b\x20\x3d\x20\x7b\x30\x31\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x28\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x7c\x20\x31\x33\x20\x30\x30\x20\x30\x30\x20\x30\x30\x29\x20\x20\x30\x30\x20\x30\x30\x20\x20\x20\x20\x20\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x20\x20\x20\x20\x20\x30\x30\x20\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30\x30\x20\x28\x30\x38\x7c\x31\x30\x29\x20\x30\x30\x20\x30\x30\x20\x30\x30\x20\x28\x30\x38\x7c\x31\x30\x29\x20\x30\x30\x20\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30\x31\x20\x30\x30\x20\x30\x31\x20\x30\x30\x20\x7d\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x41\x47\x45\x53\x41\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x47\x45\x53\x41\x20\x3d\x20\x7b\x34\x31\x20\x34\x64\x20\x34\x34\x20\x32\x31\x20\x34\x37\x20\x34\x35\x20\x35\x33\x20\x34\x31\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x7d\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x47\x45\x53\x41\x20\x3d\x20\x2f\x41\x47\x45\x53\x41\x21\x5b\x30\x2d\x39\x61\x2d\x7a\x41\x2d\x5a\x5d\x7b\x30\x2c\x31\x30\x7d\x5c\x78\x30\x30\x7b\x30\x2c\x31\x7d\x5b\x30\x2d\x39\x61\x2d\x7a\x41\x2d\x5a\x20\x2e\x5c\x2d\x5d\x2a\x2f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x41\x47\x45\x53\x41\x20\x3d\x20\x2f\x21\x21\x41\x47\x45\x53\x41\x5b\x30\x2d\x39\x61\x2d\x7a\x41\x2d\x5a\x20\x2e\x5c\x2d\x5d\x2a\x2f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x5f\x50\x49\x20\x3d\x20\x2f\x5c\x24\x41\x4d\x44\x5b\x41\x2d\x5a\x5d\x5b\x30\x2d\x39\x61\x2d\x7a\x41\x2d\x5a\x5d\x2a\x5b\x50\x49\x56\x70\x69\x76\x5d\x5b\x30\x2d\x39\x61\x2d\x7a\x41\x2d\x5a\x2e\x5c\x2d\x5d\x2a\x2f\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x61\x6d\x64\x48\x65\x61\x64\x65\x72\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x3d\x20\x7b\x61\x61\x20\x35\x35\x20\x61\x61\x20\x35\x35\x7d\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x61\x74\x20\x30\x78\x32\x30\x30\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x72\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x61\x74\x20\x30\x78\x38\x32\x30\x30\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x72\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x61\x74\x20\x30\x78\x43\x32\x30\x30\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x72\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x61\x74\x20\x30\x78\x45\x32\x30\x30\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x72\x20\x24\x41\x4d\x44\x48\x65\x61\x64\x65\x72\x20\x61\x74\x20\x30\x78\x46\x32\x30\x30\x30\x30\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x72\x20\x75\x69\x6e\x74\x33\x32\x28\x30\x29\x20\x3d\x3d\x20\x30\x78\x35\x35\x41\x41\x35\x35\x41\x41\x0a\x7d\x0a")

// FileYaraRulesCertificatesYara is "yara_rules/certificates.yara"
var FileYaraRulesCertificatesYara = []byte("\x72\x75\x6c\x65\x20\x43\x52\x59\x50\x54\x4f\x5f\x50\x45\x4d\x0a\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x24\x43\x45\x52\x54\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x22\x0a\x09\x24\x43\x45\x52\x54\x5f\x52\x45\x51\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x20\x52\x45\x51\x22\x0a\x09\x24\x43\x45\x52\x54\x5f\x4e\x45\x57\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x4e\x45\x57\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x22\x0a\x0a\x09\x24\x4b\x45\x59\x5f\x52\x53\x41\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x52\x53\x41\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x20\x20\x20\x20\x24\x4b\x45\x59\x5f\x44\x53\x41\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x44\x53\x41\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x20\x20\x20\x20\x24\x4b\x45\x59\x5f\x45\x43\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x45\x43\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x20\x20\x20\x20\x24\x4b\x45\x59\x5f\x45\x4e\x43\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x45\x4e\x43\x52\x59\x50\x54\x45\x44\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x09\x24\x4b\x45\x59\x5f\x4f\x50\x45\x4e\x53\x53\x48\x5f\x50\x52\x49\x56\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x4f\x50\x45\x4e\x53\x53\x48\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x09\x24\x4b\x45\x59\x5f\x53\x53\x48\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x53\x53\x48\x20\x50\x52\x49\x56\x41\x54\x45\x22\x0a\x0a\x09\x24\x4b\x45\x59\x5f\x53\x53\x48\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x53\x53\x48\x20\x50\x55\x42\x4c\x49\x43\x22\x0a\x09\x24\x4b\x45\x59\x5f\x52\x53\x41\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x52\x53\x41\x20\x50\x55\x42\x4c\x49\x43\x22\x0a\x20\x20\x20\x20\x24\x4b\x45\x59\x5f\x44\x53\x41\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x44\x53\x41\x20\x50\x55\x42\x4c\x49\x43\x22\x0a\x20\x20\x20\x20\x24\x4b\x45\x59\x5f\x45\x43\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x45\x43\x20\x50\x55\x42\x4c\x49\x43\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x55\x42\x4c\x49\x43\x22\x0a\x0a\x09\x24\x4b\x45\x59\x5f\x50\x47\x50\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x47\x50\x20\x50\x55\x42\x4c\x49\x43\x20\x4b\x45\x59\x20\x42\x4c\x4f\x43\x4b\x22\x0a\x09\x24\x4d\x45\x53\x53\x41\x47\x45\x5f\x50\x47\x50\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x47\x50\x20\x4d\x45\x53\x53\x41\x47\x45\x22\x0a\x09\x24\x4d\x45\x53\x53\x47\x41\x45\x5f\x50\x47\x50\x5f\x53\x49\x47\x4e\x45\x44\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x47\x50\x20\x53\x49\x47\x4e\x45\x44\x20\x4d\x45\x53\x53\x41\x47\x45\x22\x0a\x09\x24\x53\x49\x47\x4e\x41\x54\x55\x52\x45\x5f\x50\x47\x50\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x20\x50\x47\x50\x20\x50\x47\x50\x20\x53\x49\x47\x4e\x41\x54\x55\x52\x45\x22\x0a\x0a\x09\x24\x52\x45\x53\x54\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x22\x0a\x09\x24\x52\x45\x53\x54\x5f\x53\x48\x4f\x52\x54\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x2d\x2d\x2d\x42\x45\x47\x49\x4e\x22\x0a\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x43\x52\x59\x50\x54\x4f\x5f\x53\x53\x48\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x09\x24\x4b\x45\x59\x5f\x50\x45\x4d\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x53\x53\x48\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x5f\x44\x53\x53\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x73\x73\x68\x2d\x64\x73\x73\x20\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x5f\x52\x53\x41\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x22\x73\x73\x68\x2d\x72\x73\x61\x20\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x5f\x45\x43\x44\x53\x41\x5f\x50\x32\x35\x36\x20\x3d\x20\x22\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x32\x35\x36\x20\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x5f\x45\x43\x44\x53\x41\x5f\x50\x33\x38\x34\x20\x3d\x20\x22\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x33\x38\x34\x20\x22\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x5f\x45\x43\x44\x53\x41\x5f\x50\x35\x32\x31\x20\x3d\x20\x22\x65\x63\x64\x73\x61\x2d\x73\x68\x61\x32\x2d\x6e\x69\x73\x74\x70\x35\x32\x31\x20\x22\x0a\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x09\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x43\x52\x59\x50\x54\x4f\x5f\x44\x45\x52\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x09\x24\x4b\x45\x59\x5f\x50\x52\x49\x56\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x3f\x3f\x20\x3f\x3f\x20\x30\x32\x20\x30\x31\x20\x30\x30\x7d\x0a\x09\x24\x4b\x45\x59\x5f\x50\x55\x42\x20\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x3f\x3f\x20\x3f\x3f\x20\x33\x30\x20\x30\x64\x20\x30\x36\x7d\x0a\x09\x24\x43\x45\x52\x54\x20\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x3f\x3f\x20\x3f\x3f\x20\x33\x30\x20\x38\x32\x20\x3f\x3f\x7d\x0a\x09\x24\x4b\x45\x59\x5f\x52\x53\x41\x5f\x50\x55\x42\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x3f\x3f\x20\x3f\x3f\x20\x30\x32\x20\x38\x32\x20\x30\x31\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x31\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x30\x45\x20\x39\x31\x20\x36\x30\x20\x33\x34\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x32\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x32\x32\x20\x33\x30\x20\x30\x44\x20\x30\x36\x7d\x20\x2f\x2f\x20\x50\x75\x62\x6b\x65\x79\x20\x69\x6e\x73\x69\x64\x65\x20\x63\x65\x72\x74\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x33\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x38\x37\x20\x33\x30\x20\x33\x35\x20\x3f\x3f\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x34\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x38\x42\x20\x38\x44\x20\x41\x46\x20\x46\x43\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x35\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x42\x37\x20\x33\x30\x20\x31\x46\x20\x30\x36\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x36\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x31\x20\x43\x39\x20\x33\x30\x20\x31\x32\x20\x30\x36\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x37\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x32\x20\x31\x43\x20\x30\x32\x20\x30\x31\x20\x30\x31\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x38\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x34\x20\x31\x3f\x20\x41\x30\x20\x30\x33\x20\x30\x32\x7d\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x39\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x44\x20\x30\x37\x20\x30\x32\x20\x30\x31\x20\x30\x31\x7d\x20\x2f\x2f\x20\x50\x52\x49\x56\x20\x6b\x65\x79\x20\x3f\x0a\x09\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x31\x30\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x44\x20\x31\x41\x20\x30\x36\x20\x30\x39\x20\x32\x41\x7d\x0a\x20\x20\x20\x20\x2f\x2f\x24\x55\x4e\x4b\x4e\x4f\x57\x4e\x20\x20\x20\x20\x20\x3d\x20\x7b\x33\x30\x20\x38\x32\x20\x30\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x20\x3f\x3f\x7d\x0a\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x09\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d")

// FileYaraRulesCopyrightYara is "yara_rules/copyright.yara"
var FileYaraRulesCopyrightYara = []byte("\x72\x75\x6c\x65\x20\x43\x4f\x4d\x50\x41\x4e\x59\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x70\x68\x6f\x65\x6e\x69\x78\x20\x3d\x20\x22\x50\x68\x6f\x65\x6e\x69\x78\x20\x54\x65\x63\x68\x6e\x6f\x6c\x6f\x67\x69\x65\x73\x22\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x61\x77\x61\x72\x64\x20\x3d\x20\x22\x41\x77\x61\x72\x64\x20\x53\x6f\x66\x74\x77\x61\x72\x65\x22\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x61\x6d\x69\x20\x3d\x20\x22\x41\x6d\x65\x72\x69\x63\x61\x6e\x20\x4d\x65\x67\x61\x74\x72\x65\x6e\x64\x73\x22\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x43\x4f\x50\x59\x52\x49\x47\x48\x54\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x63\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x3d\x20\x2f\x63\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x5b\x61\x2d\x7a\x30\x2d\x39\x5c\x3b\x5c\x5f\x5c\x2e\x5c\x2d\x5c\x28\x5c\x29\x28\x20\x5d\x2a\x2f\x20\x6e\x6f\x63\x61\x73\x65\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x56\x45\x4e\x44\x4f\x52\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x69\x6e\x74\x65\x6c\x20\x3d\x20\x22\x49\x6e\x74\x65\x6c\x28\x52\x29\x22\x20\x6e\x6f\x63\x61\x73\x65\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x20\x3d\x20\x22\x41\x4d\x44\x22\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d")

// FileYaraRulesIntelYara is "yara_rules/intel.yara"
var FileYaraRulesIntelYara = []byte("\x0a\x72\x75\x6c\x65\x20\x46\x53\x50\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x46\x53\x50\x5f\x48\x45\x41\x44\x45\x52\x20\x3d\x20\x22\x46\x53\x50\x48\x22\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a\x0a\x72\x75\x6c\x65\x20\x69\x6e\x74\x65\x6c\x5f\x62\x6f\x6f\x74\x67\x75\x61\x72\x64\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x61\x63\x62\x70\x20\x3d\x20\x22\x5f\x5f\x41\x43\x42\x50\x5f\x5f\x22\x20\x2f\x2f\x20\x42\x6f\x6f\x74\x50\x6f\x6c\x69\x63\x79\x4d\x61\x6e\x69\x66\x65\x73\x74\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x6b\x65\x79\x6d\x20\x3d\x20\x22\x5f\x5f\x4b\x45\x59\x4d\x5f\x5f\x22\x20\x2f\x2f\x20\x4b\x65\x79\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x69\x62\x62\x73\x20\x3d\x20\x22\x5f\x5f\x49\x42\x42\x53\x5f\x5f\x22\x20\x2f\x2f\x20\x42\x6f\x6f\x74\x42\x6c\x6f\x63\x6b\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x70\x6d\x73\x67\x20\x3d\x20\x22\x5f\x5f\x50\x4d\x53\x47\x5f\x5f\x22\x20\x2f\x2f\x20\x42\x6f\x6f\x74\x50\x6f\x6c\x69\x63\x79\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x0a\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a")

// FileYaraRulesMicrocodeYara is "yara_rules/microcode.yara"
var FileYaraRulesMicrocodeYara = []byte("\x0a\x0a\x2f\x2f\x23\x20\x49\x6e\x74\x65\x6c\x20\x2d\x20\x48\x65\x61\x64\x65\x72\x52\x65\x76\x20\x30\x31\x2c\x20\x4c\x6f\x61\x64\x65\x72\x52\x65\x76\x20\x30\x31\x2c\x20\x50\x72\x6f\x63\x65\x73\x46\x6c\x61\x67\x73\x20\x78\x78\x30\x30\x2a\x33\x20\x28\x49\x6e\x74\x65\x6c\x20\x36\x34\x20\x61\x6e\x64\x20\x49\x41\x2d\x33\x32\x20\x41\x72\x63\x68\x69\x74\x65\x63\x74\x75\x72\x65\x73\x20\x53\x6f\x66\x74\x77\x61\x72\x65\x20\x44\x65\x76\x65\x6c\x6f\x70\x65\x72\x27\x73\x20\x4d\x61\x6e\x75\x61\x6c\x20\x56\x6f\x6c\x20\x33\x41\x2c\x20\x43\x68\x20\x39\x2e\x31\x31\x2e\x31\x29\x0a\x2f\x2f\x70\x61\x74\x5f\x69\x63\x70\x75\x20\x3d\x20\x72\x65\x2e\x63\x6f\x6d\x70\x69\x6c\x65\x28\x62\x72\x27\x5c\x78\x30\x31\x5c\x78\x30\x30\x7b\x33\x7d\x2e\x7b\x34\x7d\x5b\x5c\x78\x30\x30\x2d\x5c\x78\x39\x39\x5d\x28\x28\x5b\x5c\x78\x31\x39\x5c\x78\x32\x30\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x33\x31\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x31\x32\x5d\x29\x7c\x28\x5c\x78\x31\x38\x5c\x78\x30\x37\x5c\x78\x30\x30\x29\x29\x2e\x7b\x38\x7d\x5c\x78\x30\x31\x5c\x78\x30\x30\x7b\x33\x7d\x2e\x5c\x78\x30\x30\x7b\x33\x7d\x27\x2c\x20\x72\x65\x2e\x44\x4f\x54\x41\x4c\x4c\x29\x0a\x0a\x2f\x2f\x23\x20\x41\x4d\x44\x20\x2d\x20\x59\x65\x61\x72\x20\x32\x30\x78\x78\x2c\x20\x4d\x6f\x6e\x74\x68\x20\x31\x2d\x31\x33\x2c\x20\x4c\x6f\x61\x64\x65\x72\x49\x44\x20\x30\x30\x2d\x30\x34\x2c\x20\x44\x61\x74\x61\x53\x69\x7a\x65\x20\x30\x30\x7c\x31\x30\x7c\x32\x30\x2c\x20\x49\x6e\x69\x74\x46\x6c\x61\x67\x20\x30\x30\x2d\x30\x31\x2c\x20\x4e\x6f\x72\x74\x68\x42\x72\x69\x64\x67\x65\x56\x45\x4e\x5f\x49\x44\x20\x30\x30\x30\x30\x7c\x31\x30\x32\x32\x2c\x20\x53\x6f\x75\x74\x68\x42\x72\x69\x64\x67\x65\x56\x45\x4e\x5f\x49\x44\x20\x30\x30\x30\x30\x7c\x31\x30\x32\x32\x2c\x20\x42\x69\x6f\x73\x41\x70\x69\x52\x45\x56\x5f\x49\x44\x20\x30\x30\x2d\x30\x31\x2c\x20\x52\x65\x73\x65\x72\x76\x65\x64\x20\x30\x30\x7c\x41\x41\x0a\x2f\x2f\x70\x61\x74\x5f\x61\x63\x70\x75\x20\x3d\x20\x72\x65\x2e\x63\x6f\x6d\x70\x69\x6c\x65\x28\x62\x72\x27\x5c\x78\x32\x30\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x33\x31\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x31\x33\x5d\x2e\x7b\x34\x7d\x5b\x5c\x78\x30\x30\x2d\x5c\x78\x30\x34\x5d\x5c\x78\x38\x30\x5b\x5c\x78\x30\x30\x5c\x78\x32\x30\x5c\x78\x31\x30\x5d\x5b\x5c\x78\x30\x30\x5c\x78\x30\x31\x5d\x2e\x7b\x34\x7d\x28\x28\x5c\x78\x30\x30\x7b\x32\x7d\x29\x7c\x28\x5c\x78\x32\x32\x5c\x78\x31\x30\x29\x29\x2e\x7b\x32\x7d\x28\x28\x5c\x78\x30\x30\x7b\x32\x7d\x29\x7c\x28\x5c\x78\x32\x32\x5c\x78\x31\x30\x29\x29\x2e\x7b\x36\x7d\x5b\x5c\x78\x30\x30\x5c\x78\x30\x31\x5d\x28\x5c\x78\x30\x30\x7b\x33\x7d\x7c\x5c\x78\x41\x41\x7b\x33\x7d\x29\x27\x2c\x20\x72\x65\x2e\x44\x4f\x54\x41\x4c\x4c\x29\x0a\x0a\x2f\x2f\x23\x20\x56\x49\x41\x20\x2d\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x52\x52\x41\x53\x2c\x20\x4c\x6f\x61\x64\x65\x72\x20\x52\x65\x76\x69\x73\x69\x6f\x6e\x20\x30\x31\x0a\x2f\x2f\x70\x61\x74\x5f\x76\x63\x70\x75\x20\x3d\x20\x72\x65\x2e\x63\x6f\x6d\x70\x69\x6c\x65\x28\x62\x72\x27\x5c\x78\x35\x32\x5c\x78\x35\x32\x5c\x78\x34\x31\x5c\x78\x35\x33\x2e\x7b\x31\x36\x7d\x5c\x78\x30\x31\x5c\x78\x30\x30\x7b\x33\x7d\x27\x2c\x20\x72\x65\x2e\x44\x4f\x54\x41\x4c\x4c\x29\x0a\x0a\x2f\x2f\x23\x20\x46\x72\x65\x65\x73\x63\x61\x6c\x65\x20\x2d\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x51\x45\x46\x2c\x20\x48\x65\x61\x64\x65\x72\x20\x52\x65\x76\x69\x73\x69\x6f\x6e\x20\x30\x31\x0a\x2f\x2f\x70\x61\x74\x5f\x66\x63\x70\x75\x20\x3d\x20\x72\x65\x2e\x63\x6f\x6d\x70\x69\x6c\x65\x28\x62\x72\x27\x5c\x78\x35\x31\x5c\x78\x34\x35\x5c\x78\x34\x36\x5c\x78\x30\x31\x2e\x7b\x36\x32\x7d\x5b\x5c\x78\x30\x30\x2d\x5c\x78\x30\x31\x5d\x27\x2c\x20\x72\x65\x2e\x44\x4f\x54\x41\x4c\x4c\x29\x0a\x0a\x0a\x72\x75\x6c\x65\x20\x4d\x49\x43\x52\x4f\x43\x4f\x44\x45\x20\x7b\x0a\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x49\x4e\x54\x45\x4c\x20\x20\x20\x20\x20\x3d\x20\x2f\x5c\x78\x30\x31\x5c\x78\x30\x30\x7b\x33\x7d\x2e\x7b\x34\x7d\x5b\x5c\x78\x30\x30\x2d\x5c\x78\x39\x39\x5d\x28\x28\x5b\x5c\x78\x31\x39\x5c\x78\x32\x30\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x33\x31\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x31\x32\x5d\x29\x7c\x28\x5c\x78\x31\x38\x5c\x78\x30\x37\x5c\x78\x30\x30\x29\x29\x2e\x7b\x38\x7d\x5c\x78\x30\x31\x5c\x78\x30\x30\x7b\x33\x7d\x2e\x5c\x78\x30\x30\x7b\x33\x7d\x2f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x41\x4d\x44\x20\x20\x20\x20\x20\x20\x20\x3d\x20\x2f\x5c\x78\x32\x30\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x33\x31\x5d\x5b\x5c\x78\x30\x31\x2d\x5c\x78\x31\x33\x5d\x2e\x7b\x34\x7d\x5b\x5c\x78\x30\x30\x2d\x5c\x78\x30\x34\x5d\x5c\x78\x38\x30\x5b\x5c\x78\x30\x30\x5c\x78\x32\x30\x5c\x78\x31\x30\x5d\x5b\x5c\x78\x30\x30\x5c\x78\x30\x31\x5d\x2e\x7b\x34\x7d\x28\x28\x5c\x78\x30\x30\x7b\x32\x7d\x29\x7c\x28\x5c\x78\x32\x32\x5c\x78\x31\x30\x29\x29\x2e\x7b\x32\x7d\x28\x28\x5c\x78\x30\x30\x7b\x32\x7d\x29\x7c\x28\x5c\x78\x32\x32\x5c\x78\x31\x30\x29\x29\x2e\x7b\x36\x7d\x5b\x5c\x78\x30\x30\x5c\x78\x30\x31\x5d\x28\x5c\x78\x30\x30\x7b\x33\x7d\x7c\x5c\x78\x41\x41\x7b\x33\x7d\x29\x2f\x0a\x0a\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x6e\x79\x20\x6f\x66\x20\x74\x68\x65\x6d\x0a\x7d\x0a")

// FileYaraRulesSpdYara is "yara_rules/spd.yara"
var FileYaraRulesSpdYara = []byte("\x72\x75\x6c\x65\x20\x53\x50\x44\x5f\x46\x49\x4c\x45\x0a\x7b\x0a\x20\x20\x20\x20\x20\x20\x6d\x65\x74\x61\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x61\x75\x74\x68\x6f\x72\x3d\x22\x6d\x69\x6d\x6f\x6a\x61\x20\x3c\x63\x6f\x72\x65\x62\x6f\x6f\x74\x40\x6d\x69\x6d\x6f\x6a\x61\x2e\x64\x65\x3e\x22\x0a\x20\x20\x20\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x73\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x53\x50\x44\x34\x20\x3d\x20\x7b\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x32\x31\x20\x7c\x20\x32\x32\x20\x7c\x20\x32\x33\x20\x7c\x20\x32\x34\x20\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x31\x30\x20\x7c\x20\x31\x31\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x42\x20\x7c\x20\x30\x43\x20\x7c\x20\x30\x44\x20\x7c\x20\x30\x45\x20\x7c\x20\x30\x46\x20\x7c\x20\x31\x30\x20\x7c\x20\x31\x31\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x30\x20\x7c\x20\x30\x31\x20\x7c\x20\x30\x32\x20\x7c\x20\x30\x33\x20\x7c\x20\x30\x34\x7c\x20\x30\x35\x20\x7c\x20\x30\x36\x20\x7c\x20\x30\x38\x20\x7c\x20\x30\x39\x20\x7c\x20\x30\x44\x20\x7c\x20\x30\x45\x20\x7c\x20\x30\x46\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x3f\x20\x7c\x20\x31\x3f\x20\x7c\x20\x33\x3f\x20\x7c\x20\x34\x3f\x20\x7c\x20\x35\x3f\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x3f\x3f\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x3f\x3f\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x3f\x20\x7c\x20\x31\x3f\x20\x7c\x20\x32\x3f\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x30\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x3f\x30\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x3f\x3f\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x30\x20\x7c\x20\x30\x31\x20\x7c\x20\x30\x32\x20\x7c\x20\x30\x33\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x5b\x36\x5d\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x28\x30\x41\x20\x7c\x20\x30\x39\x20\x7c\x20\x30\x38\x20\x7c\x20\x30\x37\x20\x7c\x20\x30\x36\x20\x7c\x20\x30\x35\x20\x7c\x20\x30\x34\x20\x7c\x20\x30\x33\x29\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2f\x2a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x5b\x34\x39\x35\x5d\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x3f\x3f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2a\x2f\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x7d\x0a\x0a\x20\x20\x20\x20\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\x3a\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x24\x53\x50\x44\x34\x0a\x0a\x7d")



func init() {
  err := CTX.Err()
  if err != nil {
		panic(err)
	}






  
  err = FS.Mkdir(CTX, "yara_rules/", 0777)
  if err != nil && err != os.ErrExist {
    panic(err)
  }
  




  
  var f webdav.File
  

  

  
  

  f, err = FS.OpenFile(CTX, "yara_rules/amd.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesAmdYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  
  

  f, err = FS.OpenFile(CTX, "yara_rules/certificates.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesCertificatesYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  
  

  f, err = FS.OpenFile(CTX, "yara_rules/copyright.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesCopyrightYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  
  

  f, err = FS.OpenFile(CTX, "yara_rules/intel.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesIntelYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  
  

  f, err = FS.OpenFile(CTX, "yara_rules/microcode.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesMicrocodeYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  
  

  f, err = FS.OpenFile(CTX, "yara_rules/spd.yara", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
  if err != nil {
    panic(err)
  }

  
  _, err = f.Write(FileYaraRulesSpdYara)
  if err != nil {
    panic(err)
  }
  

  err = f.Close()
  if err != nil {
    panic(err)
  }
  


  Handler = &webdav.Handler{
    FileSystem: FS,
    LockSystem: webdav.NewMemLS(),
  }


}



// Open a file
func (hfs *HTTPFS) Open(path string) (http.File, error) {
  path = hfs.Prefix + path


  f, err := FS.OpenFile(CTX, path, os.O_RDONLY, 0644)
  if err != nil {
    return nil, err
  }

  return f, nil
}

// ReadFile is adapTed from ioutil
func ReadFile(path string) ([]byte, error) {
  f, err := FS.OpenFile(CTX, path, os.O_RDONLY, 0644)
  if err != nil {
    return nil, err
  }

  buf := bytes.NewBuffer(make([]byte, 0, bytes.MinRead))

  // If the buffer overflows, we will get bytes.ErrTooLarge.
  // Return that as an error. Any other panic remains.
  defer func() {
    e := recover()
    if e == nil {
      return
    }
    if panicErr, ok := e.(error); ok && panicErr == bytes.ErrTooLarge {
      err = panicErr
    } else {
      panic(e)
    }
  }()
  _, err = buf.ReadFrom(f)
  return buf.Bytes(), err
}

// WriteFile is adapTed from ioutil
func WriteFile(filename string, data []byte, perm os.FileMode) error {
  f, err := FS.OpenFile(CTX, filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
  if err != nil {
    return err
  }
  n, err := f.Write(data)
  if err == nil && n < len(data) {
    err = io.ErrShortWrite
  }
  if err1 := f.Close(); err == nil {
    err = err1
  }
  return err
}

// WalkDirs looks for files in the given dir and returns a list of files in it
// usage for all files in the b0x: WalkDirs("", false)
func WalkDirs(name string, includeDirsInList bool, files ...string) ([]string, error) {
	f, err := FS.OpenFile(CTX, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	fileInfos, err := f.Readdir(0)
	if err != nil {
    return nil, err
  }
  
  err = f.Close()
  if err != nil {
		return nil, err
	}

	for _, info := range fileInfos {
		filename := path.Join(name, info.Name())

		if includeDirsInList || !info.IsDir() {
			files = append(files, filename)
		}

		if info.IsDir() {
			files, err = WalkDirs(filename, includeDirsInList, files...)
			if err != nil {
				return nil, err
			}
		}
	}

	return files, nil
}


