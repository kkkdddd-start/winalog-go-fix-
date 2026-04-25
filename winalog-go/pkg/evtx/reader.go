package evtx

import (
	"bufio"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

var (
	ErrInvalidMagic  = errors.New("invalid EVTX magic number")
	ErrInvalidHeader = errors.New("invalid EVTX header")
	ErrInvalidChunk  = errors.New("invalid EVTX chunk")
)

type File struct {
	path   string
	reader *os.File
	header *Header
	chunks []*Chunk
}

type Header struct {
	Magic        [8]byte
	Version      uint64
	StartChunks  uint64
	EndChunks    uint64
	NextRecordID uint64
	HeaderSize   uint64
	MinorVersion uint16
	MajorVersion uint16
}

type Chunk struct {
	Offset           int64
	HeaderSize       uint64
	Signature        uint32
	ChunkNumber      uint32
	CompressedSize   uint32
	UncompressedSize uint32
	CRC32            uint32
}

type Record struct {
	XMLName   xml.Name          `xml:"Event"`
	RecordID  uint64            `json:"-"`
	Timestamp time.Time         `json:"timestamp"`
	EventID   uint16            `json:"event_id"`
	Level     uint16            `json:"level"`
	Provider  string            `json:"provider"`
	Channel   string            `json:"channel"`
	Computer  string            `json:"computer"`
	User      *string           `json:"user,omitempty"`
	RawXML    string            `json:"xml"`
	Data      map[string]string `json:"data,omitempty"`
}

func Open(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	evtx := &File{
		path:   path,
		reader: file,
	}

	if err := evtx.readHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return evtx, nil
}

func (f *File) readHeader() error {
	header := &Header{}
	if err := binary.Read(f.reader, binary.LittleEndian, header); err != nil {
		return err
	}

	if string(header.Magic[:]) != "ElfFile\x00" {
		return ErrInvalidMagic
	}

	f.header = header
	return nil
}

func (f *File) Read() (*Record, error) {
	for {
		sizeBuf := make([]byte, 4)
		_, err := io.ReadFull(f.reader, sizeBuf)
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		size := binary.LittleEndian.Uint32(sizeBuf)
		if size == 0 {
			continue
		}

		data := make([]byte, size-4)
		if _, err := io.ReadFull(f.reader, data); err != nil {
			return nil, err
		}

		return parseRecord(data)
	}
}

func parseRecord(data []byte) (*Record, error) {
	rec := &Record{
		Data: make(map[string]string),
	}

	if len(data) < 24 {
		return nil, ErrInvalidChunk
	}

	rec.RecordID = binary.LittleEndian.Uint64(data[0:8])
	timestamp := int64(binary.LittleEndian.Uint64(data[8:16]))
	rec.Timestamp = time.Unix(0, timestamp*100)

	rec.EventID = binary.LittleEndian.Uint16(data[16:18])
	rec.Level = binary.LittleEndian.Uint16(data[18:20])

	xmlData := string(data)
	if strings.Contains(xmlData, "<Event") {
		if err := xml.Unmarshal([]byte(xmlData), rec); err != nil {
		}
		if rec.RawXML == "" {
			rec.RawXML = extractXML(string(data))
		}
	}

	return rec, nil
}

func extractXML(data string) string {
	start := strings.Index(data, "<Event")
	if start == -1 {
		return ""
	}
	end := strings.Index(data[start:], "</Event>")
	if end == -1 {
		return ""
	}
	end += start + len("</Event>")
	return data[start:end]
}

func (f *File) Close() error {
	return f.reader.Close()
}

func (f *File) ReadAll() ([]*Record, error) {
	records := make([]*Record, 0)

	for {
		rec, err := f.Read()
		if err != nil {
			return records, err
		}
		if rec == nil {
			break
		}
		records = append(records, rec)
	}

	return records, nil
}

func (f *File) ReadChunk(chunkNum int) (*Chunk, error) {
	if f.header == nil {
		return nil, ErrInvalidHeader
	}

	offset := int64(f.header.HeaderSize) + int64(chunkNum)*int64(4096*64)

	if _, err := f.reader.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	chunk := &Chunk{Offset: offset}
	if err := binary.Read(f.reader, binary.LittleEndian, chunk); err != nil {
		return nil, err
	}

	return chunk, nil
}

func (f *File) ParseXML() ([]*Record, error) {
	f.reader.Seek(0, io.SeekStart)
	scanner := bufio.NewScanner(f.reader)

	var xmlBuf string
	var records []*Record

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "<Event") {
			xmlBuf = line
		} else if xmlBuf != "" {
			xmlBuf += line
		}

		if strings.Contains(xmlBuf, "</Event>") {
			rec := &Record{RawXML: xmlBuf}
			if err := xml.Unmarshal([]byte(xmlBuf), rec); err == nil {
				records = append(records, rec)
			}
			xmlBuf = ""
		}
	}

	return records, nil
}

type RecordScanner struct {
	file    *os.File
	lastErr error
}

func NewRecordScanner(path string) (*RecordScanner, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 24)
	if _, err := file.Read(header); err != nil {
		file.Close()
		return nil, err
	}

	if string(header[:8]) != "ElfFile\x00" {
		file.Close()
		return nil, ErrInvalidMagic
	}

	return &RecordScanner{file: file}, nil
}

func (s *RecordScanner) Scan() bool {
	return s.lastErr == nil
}

func (s *RecordScanner) Record() (*Record, error) {
	return s.nextRecord()
}

func (s *RecordScanner) nextRecord() (*Record, error) {
	sizeBuf := make([]byte, 4)
	_, err := s.file.Read(sizeBuf)
	if err != nil {
		s.lastErr = err
		return nil, err
	}

	size := binary.LittleEndian.Uint32(sizeBuf)
	if size == 0 || size > 1024*1024 {
		return s.nextRecord()
	}

	data := make([]byte, size-4)
	if _, err := io.ReadFull(s.file, data); err != nil {
		s.lastErr = err
		return nil, err
	}

	rec, err := parseRecord(data)
	if err != nil {
		s.lastErr = err
	}
	return rec, err
}

func (s *RecordScanner) Close() error {
	return s.file.Close()
}

type chunkReader struct {
	f    *os.File
	size int64
	pos  int64
}

func newChunkReader(path string) (*chunkReader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return &chunkReader{
		f:    f,
		size: info.Size(),
	}, nil
}

func (r *chunkReader) readAt(offset int64, size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := r.f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

func (r *chunkReader) close() error {
	return r.f.Close()
}

type XMLRecord struct {
	XMLName   xml.Name `xml:"Event"`
	Text      string   `xml:",chardata"`
	XML       string   `xml:",innerxml"`
	System    XMLSystem
	EventData struct {
		XMLName xml.Name `xml:"EventData"`
		Data    []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

type XMLSystem struct {
	XMLName  xml.Name `xml:"System"`
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID     string `xml:"EventID"`
	Level       string `xml:"Level"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Computer string `xml:"Computer"`
}
