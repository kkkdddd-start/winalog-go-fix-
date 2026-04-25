package forensics

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

type HashResult struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256"`
	MD5      string `json:"md5,omitempty"`
	SHA1     string `json:"sha1,omitempty"`
	Size     int64  `json:"size"`
}

func CalculateFileHash(path string) (*HashResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	sha256Hash := sha256.New()
	md5Hash := md5.New()
	sha1Hash := sha1.New()

	writer := io.MultiWriter(sha256Hash, md5Hash, sha1Hash)

	if _, err := io.Copy(writer, file); err != nil {
		return nil, err
	}

	return &HashResult{
		FilePath: path,
		SHA256:   hex.EncodeToString(sha256Hash.Sum(nil)),
		MD5:      hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:     hex.EncodeToString(sha1Hash.Sum(nil)),
		Size:     info.Size(),
	}, nil
}

func VerifyFileHash(path, expectedSHA256 string) (bool, *HashResult, error) {
	result, err := CalculateFileHash(path)
	if err != nil {
		return false, nil, err
	}
	return result.SHA256 == expectedSHA256, result, nil
}
