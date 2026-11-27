package account

import (
	"bytes"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	keychainSuccess   int32 = 0
	keychainNotFound  int32 = -25300
	keychainDuplicate int32 = -25299
)

type keychainAPI struct {
	find    func(uintptr, uint32, *byte, uint32, *byte, *uint32, *unsafe.Pointer, *uintptr) int32
	add     func(uintptr, uint32, *byte, uint32, *byte, uint32, *byte, *uintptr) int32
	update  func(uintptr, uintptr, uint32, *byte) int32
	delete  func(uintptr) int32
	free    func(uintptr, unsafe.Pointer) int32
	release func(uintptr)
}

var nativeKeychain = sync.OnceValues(func() (keychainAPI, error) {
	const frameworks = "/System/Library/Frameworks/"
	security, err := purego.Dlopen(frameworks+"Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return keychainAPI{}, err
	}
	foundation, err := purego.Dlopen(frameworks+"CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return keychainAPI{}, err
	}
	var keychain keychainAPI
	purego.RegisterLibFunc(&keychain.find, security, "SecKeychainFindGenericPassword")
	purego.RegisterLibFunc(&keychain.add, security, "SecKeychainAddGenericPassword")
	purego.RegisterLibFunc(&keychain.update, security, "SecKeychainItemModifyAttributesAndData")
	purego.RegisterLibFunc(&keychain.delete, security, "SecKeychainItemDelete")
	purego.RegisterLibFunc(&keychain.free, security, "SecKeychainItemFreeContent")
	purego.RegisterLibFunc(&keychain.release, foundation, "CFRelease")
	return keychain, nil
})

func keychainError(status int32) error {
	switch status {
	case keychainSuccess:
		return nil
	case keychainNotFound:
		return errKeychainItemNotFound
	default:
		return fmt.Errorf("Security.framework status %d", status)
	}
}

func (k keychainAPI) findItem(service, account string, size *uint32, data *unsafe.Pointer, item *uintptr) int32 {
	return k.find(0, uint32(len(service)), unsafe.StringData(service), uint32(len(account)), unsafe.StringData(account), size, data, item)
}

func readNativeKeychainItem(service, account string) ([]byte, error) {
	k, err := nativeKeychain()
	if err != nil {
		return nil, err
	}
	var size uint32
	var data unsafe.Pointer
	if err := keychainError(k.findItem(service, account, &size, &data, nil)); err != nil {
		return nil, err
	}
	if data != nil {
		defer k.free(0, data)
	}
	return bytes.Clone(unsafe.Slice((*byte)(data), size)), nil
}

func writeNativeKeychainItem(service, account string, value []byte) error {
	k, err := nativeKeychain()
	if err != nil {
		return err
	}
	data := unsafe.SliceData(value)
	if len(value) == 0 {
		data = new(byte)
	}
	status := k.add(0, uint32(len(service)), unsafe.StringData(service), uint32(len(account)), unsafe.StringData(account), uint32(len(value)), data, nil)
	if status != keychainDuplicate {
		return keychainError(status)
	}
	var item uintptr
	if err := keychainError(k.findItem(service, account, nil, nil, &item)); err != nil {
		return err
	}
	defer k.release(item)
	return keychainError(k.update(item, 0, uint32(len(value)), data))
}

func deleteNativeKeychainItem(service, account string) error {
	k, err := nativeKeychain()
	if err != nil {
		return err
	}
	var item uintptr
	if err := keychainError(k.findItem(service, account, nil, nil, &item)); err != nil {
		return err
	}
	defer k.release(item)
	return keychainError(k.delete(item))
}
