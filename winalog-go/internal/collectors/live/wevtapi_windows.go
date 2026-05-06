//go:build windows

package live

import (
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"golang.org/x/sys/windows"
)

var (
	wevtapi = windows.NewLazyDLL("wevtapi.dll")

	procEvtQuery            = wevtapi.NewProc("EvtQuery")
	procEvtSubscribe        = wevtapi.NewProc("EvtSubscribe")
	procEvtNext             = wevtapi.NewProc("EvtNext")
	procEvtClose            = wevtapi.NewProc("EvtClose")
	procEvtRender           = wevtapi.NewProc("EvtRender")
	procEvtOpenChannelEnum  = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath  = wevtapi.NewProc("EvtNextChannelPath")
	procEvtCreateBookmark   = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark   = wevtapi.NewProc("EvtUpdateBookmark")
	procEvtGetBookmarkXML   = wevtapi.NewProc("EvtGetBookmarkXML")
)

const (
	EvtSubscribeToExistingEvents   = 1
	EvtSubscribeStartAfterBookmark = 2
	EvtSubscribeActionStartAtOldestRecord = 0
	EvtSubscribeActionStartAfterBookmark  = 1

	EvtQueryChannelPath       = 0x00000001
	EvtQueryReverseDirection  = 0x00000004

	EvtRenderEventXML = 1

	INFINITE = 0xFFFFFFFF
)

func renderEvent(eventHandle windows.Handle) *types.Event {
	if eventHandle == 0 {
		return nil
	}

	var bufferSize uint32
	procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXML),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if bufferSize == 0 {
		return nil
	}

	buffer := make([]byte, bufferSize)
	ret, _, _ := procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXML),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		0,
	)

	if ret == 0 {
		return nil
	}

	// EvtRender returns UTF-16LE data. Convert to Go string.
	ptr := (*[1 << 20]uint16)(unsafe.Pointer(&buffer[0]))
	length := int(bufferSize)/2 - 1
	if length < 0 {
		return nil
	}
	xmlStr := windows.UTF16ToString(ptr[:length])

	return ParseEventXML(xmlStr)
}
