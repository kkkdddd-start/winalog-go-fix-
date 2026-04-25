//go:build windows

package utils

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

var registryHiveMap = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE,
	"HKCU": registry.CURRENT_USER,
	"HKCR": registry.CLASSES_ROOT,
	"HKU":  registry.USERS,
}

func ListRegistrySubkeys(path string) ([]string, error) {
	hive, subkey, _ := ParseRegistryPath(path)
	if hive == "" || subkey == "" {
		return []string{}, nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return []string{}, nil
	}
	defer regKey.Close()

	subkeys, err := regKey.ReadSubKeyNames(0)
	if err != nil {
		return []string{}, err
	}

	return subkeys, nil
}

func GetRegistryValue(keyPath, valueName string) (string, error) {
	hive, subkey, _ := ParseRegistryPath(keyPath)
	if hive == "" || subkey == "" {
		return "", nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return "", err
	}
	defer regKey.Close()

	if valueName == "" {
		valueName = ""
	}
	val, _, err := regKey.GetStringValue(valueName)
	if err != nil {
		return "", err
	}

	return val, nil
}

func RegistryKeyExists(path string) bool {
	hive, subkey, _ := ParseRegistryPath(path)
	if hive == "" || subkey == "" {
		return false
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return false
	}
	regKey.Close()

	return true
}

func GetRegistryStringValue(keyPath, valueName string) (string, error) {
	return GetRegistryValue(keyPath, valueName)
}

func GetRegistryDWORDValue(keyPath, valueName string) (uint32, error) {
	hive, subkey, valName := ParseRegistryPath(keyPath)
	if hive == "" || subkey == "" {
		return 0, nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return 0, err
	}
	defer regKey.Close()

	val, _, err := regKey.GetIntegerValue(valName)
	if err != nil {
		return 0, err
	}

	return uint32(val), nil
}

func GetRegistryMultiStringValue(keyPath, valueName string) ([]string, error) {
	hive, subkey, valName := ParseRegistryPath(keyPath)
	if hive == "" || subkey == "" {
		return []string{}, nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return []string{}, err
	}
	defer regKey.Close()

	val, _, err := regKey.GetStringValue(valName)
	if err != nil {
		return []string{}, err
	}

	return []string{val}, nil
}

func ParseRegistryPath(path string) (hive, subkey, value string) {
	path = strings.TrimPrefix(path, `\\`)

	parts := strings.SplitN(path, `\`, 2)
	if len(parts) < 2 {
		return "", "", ""
	}

	hive = strings.ToUpper(parts[0])
	subkey = parts[1]

	return hive, subkey, ""
}

func NormalizeRegistryPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "/", "\\")
	path = strings.ReplaceAll(path, "\\\\", "\\")

	return strings.ToUpper(path)
}

func ListRegistryValues(path string) ([]string, error) {
	hive, subkey, _ := ParseRegistryPath(path)
	if hive == "" || subkey == "" {
		return []string{}, nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return []string{}, nil
	}
	defer regKey.Close()

	values, err := regKey.ReadValueNames(0)
	if err != nil {
		return []string{}, err
	}

	return values, nil
}

func GetRegistryStringValueFull(keyPath string) (map[string]string, error) {
	result := make(map[string]string)

	hive, subkey, _ := ParseRegistryPath(keyPath)
	if hive == "" || subkey == "" {
		return result, nil
	}

	key, ok := registryHiveMap[hive]
	if !ok {
		key = registry.LOCAL_MACHINE
	}

	regKey, err := registry.OpenKey(key, subkey, registry.READ)
	if err != nil {
		return result, err
	}
	defer regKey.Close()

	valueNames, err := regKey.ReadValueNames(0)
	if err != nil {
		return result, err
	}

	for _, name := range valueNames {
		if val, _, err := regKey.GetStringValue(name); err == nil {
			result[name] = val
		}
	}

	return result, nil
}
