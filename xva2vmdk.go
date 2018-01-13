package main

import (
	"flag"
	"log"
	"archive/tar"
	"os"
	"io"
	"strings"
	"strconv"
	"path/filepath"
	"fmt"
	"math/rand"
	"time"
	"io/ioutil"
	"crypto/sha1"
	"encoding/hex"
)

var (
	f_out = flag.String("o", "", "output directory (defaults to image dir)")
	f_sha = flag.Bool("sha", false, "stop in case of checksum mismatch")
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		os.Exit(1)
		return
	}
	for _, path := range flag.Args() {
		if err := run(path); err != nil {
			log.Fatal(err)
		}
	}
}

func run(path string) error {
	out := *f_out
	if out == "" {
		out = filepath.Dir(path)
	}
	name := strings.TrimSuffix(filepath.Base(path), ".xva")
	log.Println("processing", name)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	rd := tar.NewReader(file)

	disks := make(map[int]*os.File)
	defer func(){
		for _, f := range disks {
			if fi, _ := f.Stat(); fi != nil {
				writeVMDK(f.Name(), fi.Size())
			}
			f.Close()
		}
	}()
	var (
		buf []byte
		lb = -1
		bs int64
		sha = sha1.New()
		chk1, chk2 [sha1.Size]byte
	)
	for {
		h, err := rd.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if !strings.HasPrefix(h.Name, "Ref:") {
			log.Println("skip", h.Name)
			continue
		}
		h.Name = strings.TrimPrefix(h.Name, "Ref:")
		i := strings.Index(h.Name, "/")
		if i < 0 {
			continue
		}
		diskn, err := strconv.Atoi(h.Name[:i])
		if err != nil {
			return err
		}
		df := disks[diskn]
		if df == nil {
			log.Printf("writing disk Ref:%d", diskn)
			dname := fmt.Sprintf("%s-disk-%d.raw", name, diskn)
			df, err = os.Create(filepath.Join(out, dname))
			if err != nil {
				return err
			}
			disks[diskn] = df
		}
		h.Name = h.Name[i+1:]
		i = strings.Index(h.Name, ".")
		if i < 0 {
			i = len(h.Name)
		}
		if i != 8 {
			return fmt.Errorf("malformed block name: %q", h.Name)
		}
		bn, err := strconv.Atoi(h.Name[:i])
		if err != nil {
			return err
		}
		if strings.HasSuffix(h.Name, ".checksum") {
			data, _ := ioutil.ReadAll(io.LimitReader(rd, 1024))
			_, err = hex.Decode(chk1[:], data)
			if err != nil {
				log.Println(err)
				continue
			}
			sha.Reset()
			off := int64(bn)*bs
			if lb != bn {
				_, err = df.ReadAt(buf[:bs], off)
				if err != nil {
					log.Println(err)
					continue
				}
			}
			sha.Write(buf[:bs])
			sha.Sum(chk2[:0])
			if chk1 != chk2 {
				err := fmt.Errorf("signature missmatch for Ref:%d block %d (offset: %x): %x vs %x",
					diskn, bn, off, chk1, chk2)
				if *f_sha {
					return err
				}
				log.Println(err)
			}
			lb = -1
			continue
		}
		lb = bn
		bs = h.Size
		off := int64(bn)*bs
		if fi, err := df.Stat(); err != nil {
			return err
		} else if sz := off+bs; sz > fi.Size() {
			if err = df.Truncate(sz); err != nil {
				return err
			}
		}
		if len(buf) < int(bs) {
			buf = make([]byte, bs)
		} else {
			buf = buf[:bs]
		}
		if _, err = io.ReadFull(rd, buf); err != nil {
			return err
		}
		if _, err = df.WriteAt(buf, off); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func writeVMDK(name string, size int64) error {
	ext := filepath.Ext(name)
	base := filepath.Base(name)
	file, err := os.Create(strings.TrimSuffix(name, ext)+".vmdk")
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintf(file,`# Disk DescriptorFile
version=1
CID=%08x
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW %d FLAT "%s" 0
`, rand.Intn(0xffffffff), size/512, base)
	return err
}