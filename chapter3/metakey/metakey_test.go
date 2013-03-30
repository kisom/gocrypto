package metakey

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func FailWithError(name, err string, t *testing.T) {
	fmt.Printf("%s: failed: %s\n", name, err)
	t.FailNow()
}

func GenFailer(name string, err error, t *testing.T) func(string) {
	return func(msg string) {
		fmt.Printf("%#v\n", err)
		if msg == "" {
			fmt.Printf("%s: failed: %s\n", name, err.Error())
		} else {
			fmt.Printf("%s: failed: %s\n", name, msg)
		}
		t.FailNow()
	}
}

func tempFileName() string {
	tmpf, err := ioutil.TempFile("", "metakey_test_")
	if err != nil {
		return ""
	}
	defer tmpf.Close()
	return tmpf.Name()
}

func TestMetaKeyCreation(t *testing.T) {
	mk, err := New("test key", 0)
	if err != nil {
		fmt.Printf("failed to create new metakey: %s\n", err.Error())
		t.FailNow()
	}
	if !mk.Valid() {
		fmt.Println("failed to initialise new metakey")
		t.FailNow()
	}
}

func TestMetaKeyReadWrite(t *testing.T) {
	var (
		err     error
		mk, mk2 *MetaKey
		buf     *bytes.Buffer
	)

	buf = new(bytes.Buffer)
	fail := GenFailer("TestMetaKeyReadWrite", err, t)

	mk, err = New("test key", 0)
	if err != nil {
		fail("")
	}

	err = mk.Write(buf)
	if err != nil {
		fail("")
	}

	mk2, err = Read(buf)
	if err != nil {
		fail("")
	} else if !mk2.Valid() {
		fail("invalid metakey read from file")
	}
}

func TestMetaKeyFileReadWrite(t *testing.T) {
	var (
		err     error
		mk, mk2 *MetaKey
	)

	fail := GenFailer("TestMetaKeyFileReadWrite", err, t)

	mk, err = New("test key", 0)
	if err != nil {
		fail("")
	}
	tmpf := tempFileName()
	if tmpf == "" {
		fail("couldn't create temp file")
	}
	defer os.Remove(tmpf)

	err = mk.WriteFile(tmpf)
	if err != nil {
		fail("")
	}

	mk2, err = ReadFile(tmpf)
	if err != nil {
		fail("")
	} else if !mk2.Valid() {
		fail("invalid metakey read from file")
	}
}

func TestMetaKeyExport(t *testing.T) {
	var err error

	fail := GenFailer("TestMetaKeyExport", err, t)

	var mk *MetaKey
	mk, err = New("test export key", 0)
	if err != nil {
		fail(err.Error())
	}
	tmpf := tempFileName()
	if tmpf == "" {
		fail("couldn't create temp file")
	}
	defer os.Remove(tmpf)

	mk.Export(tmpf)

	var mk2 *MetaKey
	mk2, err = Import(tmpf)
	if err != nil {
		fail(err.Error())
	} else if !mk2.Valid() {
		fail("invalid exported key read")
	}
}
