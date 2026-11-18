//go:build darwin && cgo

// SPDX-License-Identifier: BUSL-1.1
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static OSStatus aegis_open_keychain(SecKeychainRef *keychain) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	// A CLI can use the default file-based Keychain without application entitlements.
	return SecKeychainCopyDefault(keychain);
#pragma clang diagnostic pop
}

enum { AEGIS_READ, AEGIS_ADD, AEGIS_REPLACE, AEGIS_REMOVE };

static OSStatus aegis_keychain_item(SecKeychainRef keychain, const char *service,
	const char *account, int operation, const char *token, CFTypeRef *result) {
	OSStatus status = errSecAllocate;
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef serviceName = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
	CFStringRef accountName = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
	CFArrayRef search = NULL;
	CFDataRef value = NULL;
	CFDictionaryRef updates = NULL;
	if (!query || !serviceName || !accountName) goto cleanup;
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, serviceName);
	CFDictionarySetValue(query, kSecAttrAccount, accountName);

	if (operation == AEGIS_ADD || operation == AEGIS_REPLACE) {
		value = CFDataCreate(NULL, (const UInt8 *)token, strlen(token));
		if (!value) goto cleanup;
	}
	if (operation == AEGIS_ADD) {
		CFDictionarySetValue(query, kSecUseKeychain, keychain);
		CFDictionarySetValue(query, kSecValueData, value);
		status = SecItemAdd(query, NULL);
		goto cleanup;
	}

	const void *keychains[] = { keychain };
	search = CFArrayCreate(NULL, keychains, 1, &kCFTypeArrayCallBacks);
	if (!search) goto cleanup;
	CFDictionarySetValue(query, kSecMatchSearchList, search);
	switch (operation) {
	case AEGIS_READ:
		CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
		CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
		status = SecItemCopyMatching(query, result);
		break;
	case AEGIS_REPLACE: {
		const void *keys[] = { kSecValueData };
		const void *values[] = { value };
		updates = CFDictionaryCreate(NULL, keys, values, 1,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		if (updates) status = SecItemUpdate(query, updates);
		break;
	}
	case AEGIS_REMOVE:
		status = SecItemDelete(query);
		break;
	}
cleanup:
	if (updates) CFRelease(updates);
	if (value) CFRelease(value);
	if (search) CFRelease(search);
	if (accountName) CFRelease(accountName);
	if (serviceName) CFRelease(serviceName);
	if (query) CFRelease(query);
	return status;
}

static void aegis_release_keychain(SecKeychainRef keychain) { CFRelease(keychain); }

static CFIndex aegis_token_length(CFTypeRef item) {
	if (!item || CFGetTypeID(item) != CFDataGetTypeID()) return 0;
	return CFDataGetLength((CFDataRef)item);
}

static const UInt8 *aegis_token_bytes(CFTypeRef item) {
	return CFDataGetBytePtr((CFDataRef)item);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

type macKeychain struct {
	keychain C.SecKeychainRef
	service  string
	account  string
}

func openKeychain(base, account string) (keychainStore, error) {
	var keychain C.SecKeychainRef
	if status := C.aegis_open_keychain(&keychain); status != C.errSecSuccess {
		return nil, fmt.Errorf("could not open the default macOS Keychain (status %d)", status)
	}
	return &macKeychain{keychain, "Aegis desktop connector " + pairingHash(base), account}, nil
}

func (s *macKeychain) close() { C.aegis_release_keychain(s.keychain) }

func (s *macKeychain) read(pending bool) (string, error) {
	return s.item(pending, C.AEGIS_READ, "")
}

func (s *macKeychain) add(pending bool, token string) error {
	_, err := s.item(pending, C.AEGIS_ADD, token)
	return err
}

func (s *macKeychain) replace(token string) error {
	_, err := s.item(false, C.AEGIS_REPLACE, token)
	return err
}

func (s *macKeychain) clearPending() error {
	_, err := s.item(true, C.AEGIS_REMOVE, "")
	if errors.Is(err, errKeychainItemMissing) {
		return nil
	}
	return err
}

func (s *macKeychain) item(pending bool, operation C.int, token string) (string, error) {
	service := s.service
	if pending {
		service += " renewal"
	}
	serviceName := C.CString(service)
	defer C.free(unsafe.Pointer(serviceName))
	account := C.CString(s.account)
	defer C.free(unsafe.Pointer(account))
	var secret *C.char
	if operation == C.AEGIS_ADD || operation == C.AEGIS_REPLACE {
		if !pairedTokenShape.MatchString(token) {
			return "", errors.New("invalid paired credential")
		}
		secret = C.CString(token)
		defer C.free(unsafe.Pointer(secret))
	}
	var item C.CFTypeRef
	status := C.aegis_keychain_item(s.keychain, serviceName, account, operation, secret, &item)
	if item != 0 {
		defer C.CFRelease(item)
	}
	switch status {
	case C.errSecSuccess:
	case C.errSecItemNotFound:
		return "", errKeychainItemMissing
	case C.errSecDuplicateItem:
		return "", errors.New("a credential already exists in this Keychain slot")
	default:
		return "", fmt.Errorf("macOS Keychain operation failed (status %d)", status)
	}
	if operation != C.AEGIS_READ {
		return "", nil
	}
	length := C.aegis_token_length(item)
	if length != C.CFIndex(len("aegis_dp_")+64) {
		return "", errors.New("invalid paired credential in Keychain")
	}
	value := C.GoStringN((*C.char)(unsafe.Pointer(C.aegis_token_bytes(item))), C.int(length))
	if !pairedTokenShape.MatchString(value) {
		return "", errors.New("invalid paired credential in Keychain")
	}
	return value, nil
}

func renewKeychain(base, account string) error {
	cache, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(cache) {
		return errors.New("could not resolve the Aegis renewal lock directory")
	}
	dir := filepath.Join(cache, "aegis", "keychain")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("could not create the Aegis renewal lock directory")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	info, statErr := os.Stat(dir)
	if err != nil || canonical != dir || statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Aegis renewal lock directory must be private")
	}
	lockName := pairingHash(base + "\x00" + account)[7:] + ".lock"
	unlock, err := lockRenewal(filepath.Join(dir, lockName))
	if err != nil {
		return err
	}
	defer unlock()
	store, err := openKeychain(base, account)
	if err != nil {
		return err
	}
	defer store.close()
	return rotateKeychain(store, func(old, next string) error { return confirmRotation(base, old, next) })
}
