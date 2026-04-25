package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func FileExists(path string) (string, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return info.Name(), true, nil
}

func GetFileModTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func GetFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	buffer := make([]byte, 8192)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			hash.Write(buffer[:n])
		}
		if err != nil {
			break
		}
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func ListDirectory(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func ListFilesWithExt(path, ext string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(path)
	if err != nil {
		return files, err
	}

	ext = strings.ToLower(ext)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ext) {
			fullPath := filepath.Join(path, entry.Name())
			files = append(files, fullPath)
		}
	}

	return files, nil
}

func NormalizePath(path string) string {
	path = filepath.Clean(path)
	path = strings.ReplaceAll(path, "/", "\\")
	return path
}

func ExpandEnvironmentVariables(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}

	vars := []string{
		"SYSTEMROOT", "WINDOWS",
		"PROGRAMFILES", "PROGRAMDATA",
		"APPDATA", "LOCALAPPDATA",
		"TEMP", "TMP",
		"USERPROFILE", "HOMEPATH",
	}

	for _, v := range vars {
		envValue := os.Getenv(v)
		if envValue != "" {
			path = strings.ReplaceAll(path, "%"+v+"%", envValue)
			path = strings.ReplaceAll(path, "%"+strings.ToLower(v)+"%", envValue)
		}
	}

	return path
}

func IsPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func IsDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func IsAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}

func GetBaseName(path string) string {
	return filepath.Base(path)
}

func GetDirName(path string) string {
	return filepath.Dir(path)
}
