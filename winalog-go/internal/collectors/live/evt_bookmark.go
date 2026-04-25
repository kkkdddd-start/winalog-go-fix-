//go:build windows

package live

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procEvtCreateBookmark = windows.NewLazyDLL("wevtapi.dll").NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = windows.NewLazyDLL("wevtapi.dll").NewProc("EvtUpdateBookmark")
	procEvtGetBookmarkXML = windows.NewLazyDLL("wevtapi.dll").NewProc("EvtGetBookmarkXML")
)

type EvtBookmark struct {
	handle      windows.Handle
	channel     string
	recordID    uint64
	timeCreated string
}

func CreateEvtBookmark(channelName string) (windows.Handle, error) {
	channelPtr, _ := windows.UTF16PtrFromString(channelName)
	handle, _, err := procEvtCreateBookmark.Call(
		uintptr(unsafe.Pointer(channelPtr)),
	)
	if handle == 0 {
		return 0, err
	}
	return windows.Handle(handle), nil
}

func CreateEvtBookmarkFromXML(xmlBookmark string) (windows.Handle, error) {
	xmlPtr, _ := windows.UTF16PtrFromString(xmlBookmark)
	handle, _, err := procEvtCreateBookmark.Call(
		uintptr(unsafe.Pointer(xmlPtr)),
	)
	if handle == 0 {
		return 0, err
	}
	return windows.Handle(handle), nil
}

func UpdateEvtBookmark(bookmark windows.Handle, eventHandle windows.Handle) error {
	ret, _, err := procEvtUpdateBookmark.Call(
		uintptr(bookmark),
		uintptr(eventHandle),
	)
	if ret == 0 {
		return err
	}
	return nil
}

func GetEvtBookmarkXML(bookmark windows.Handle) (string, error) {
	var bufferSize uint32
	procEvtGetBookmarkXML.Call(
		uintptr(bookmark),
		0,
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if bufferSize == 0 {
		return "", nil
	}

	buffer := make([]uint16, bufferSize)
	ret, _, err := procEvtGetBookmarkXML.Call(
		uintptr(bookmark),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if ret == 0 {
		return "", err
	}

	return windows.UTF16ToString(buffer), nil
}

func ParseBookmarkXML(xmlContent string) (channel string, recordID uint64, timeCreated string) {
	lines := strings.Split(xmlContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Channel=") {
			channel = strings.TrimPrefix(line, "Channel=")
			channel = strings.Trim(channel, "\"")
		}
		if strings.HasPrefix(line, "RecordID=") {
			recordIDStr := strings.TrimPrefix(line, "RecordID=")
			recordIDStr = strings.Trim(recordIDStr, "\"")
			for _, c := range recordIDStr {
				if c >= '0' && c <= '9' {
					recordID = recordID*10 + uint64(c-'0')
				}
			}
		}
		if strings.HasPrefix(line, "TimeCreated=") {
			timeCreated = strings.TrimPrefix(line, "TimeCreated=")
			timeCreated = strings.Trim(timeCreated, "\"")
		}
	}
	return
}

func CloseEvtBookmark(bookmark windows.Handle) {
	if bookmark != 0 {
		procEvtClose.Call(uintptr(bookmark))
	}
}
