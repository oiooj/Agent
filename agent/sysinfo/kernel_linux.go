package sysinfo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/lodastack/agent/agent/common"

	"github.com/lodastack/log"
	"github.com/lodastack/nux"
)

func FsKernelMetrics() (L []*common.Metric) {
	maxFiles, err := nux.KernelMaxFiles()
	if err != nil {
		log.Error("failed collect kernel metrics:", err)
		return
	}

	L = append(L, toMetric("kernel.files.max", maxFiles, nil))

	allocateFiles, err := nux.KernelAllocateFiles()
	if err != nil {
		log.Error("failed to call KernelAllocateFiles:", err)
		return
	}

	v := common.SetPrecision(float64(allocateFiles)*100/float64(maxFiles), 2)
	L = append(L, toMetric("kernel.files.allocated", allocateFiles, nil))
	L = append(L, toMetric("kernel.files.allocated.percent", v, nil))
	L = append(L, toMetric("kernel.files.left", maxFiles-allocateFiles, nil))
	return
}

// exec `ps` to get all process states
func PsMetrics() (L []*common.Metric) {
	out, err := execPS()
	if err != nil {
		log.Error("failed to call ps command:", err)
		return
	}
	fields := make(map[string]int64)
	for i, status := range bytes.Fields(out) {
		if i == 0 && string(status) == "STAT" {
			// This is a header, skip it
			continue
		}
		switch status[0] {
		case 'W':
			fields["wait"] = fields["wait"] + int64(1)
		case 'U', 'D', 'L':
			// Also known as uninterruptible sleep or disk sleep
			fields["blocked"] = fields["blocked"] + int64(1)
		case 'Z':
			fields["zombies"] = fields["zombies"] + int64(1)
		case 'T':
			fields["stopped"] = fields["stopped"] + int64(1)
		case 'R':
			fields["running"] = fields["running"] + int64(1)
		case 'S':
			fields["sleeping"] = fields["sleeping"] + int64(1)
		case 'I':
			fields["idle"] = fields["idle"] + int64(1)
		case 'X':
			fields["exit"] = fields["exit"] + int64(1)
		case '?':
			fields["unknown"] = fields["unknown"] + int64(1)
		default:
			log.Errorf("processes: Unknown state [ %s ] from ps",
				string(status[0]))
		}
		fields["total"] = fields["total"] + int64(1)
	}
	L = append(L, toMetric("ps.zombies.num", fields["zombies"], nil))
	L = append(L, toMetric("ps.running.num", fields["running"], nil))
	L = append(L, toMetric("ps.total.num", fields["total"], nil))
	return
}

func execPS() ([]byte, error) {
	bin, err := exec.LookPath("ps")
	if err != nil {
		return nil, err
	}

	out, err := exec.Command(bin, "axo", "state").Output()
	if err != nil {
		return nil, err
	}

	return out, err
}

const (
	Empty        = 0x0
	RunLevel     = 0x1
	BootTime     = 0x2
	NewTime      = 0x3
	OldTime      = 0x4
	InitProcess  = 0x5
	LoginProcess = 0x6
	UserProcess  = 0x7
	DeadProcess  = 0x8
	Accounting   = 0x9
)

const (
	LineSize = 32
	NameSize = 32
	HostSize = 256
)

// utmp structures
// see man utmp
type ExitStatus struct {
	Termination int16
	Exit        int16
}

type TimeVal struct {
	Sec  int32
	Usec int32
}

type Utmp struct {
	Type int16
	// alignment
	_       [2]byte
	Pid     int32
	Device  [LineSize]byte
	Id      [4]byte
	User    [NameSize]byte
	Host    [HostSize]byte
	Exit    ExitStatus
	Session int32
	Time    TimeVal
	Addr    [4]int32
	// Reserved member
	Reserved [20]byte
}

// Read utmps
func Read(file io.Reader) ([]*Utmp, error) {
	var us []*Utmp

	for {
		u, readErr := readLine(file)
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
		us = append(us, u)
	}

	return us, nil
}

// read utmp
func readLine(file io.Reader) (*Utmp, error) {
	u := new(Utmp)

	err := binary.Read(file, binary.LittleEndian, u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

type GoExitStatus struct {
	Termination int
	Exit        int
}

type GoUtmp struct {
	Type    int
	Pid     int
	Device  string
	Id      string
	User    string
	Host    string
	Exit    GoExitStatus
	Session int
	Time    time.Time
	Addr    string
}

// Convert Utmp to GoUtmp
func NewGoUtmp(u *Utmp) *GoUtmp {
	return &GoUtmp{
		Type:   int(u.Type),
		Pid:    int(u.Pid),
		Device: string(u.Device[:getByteLen(u.Device[:])]),
		Id:     string(u.Id[:getByteLen(u.Id[:])]),
		User:   string(u.User[:getByteLen(u.User[:])]),
		Host:   string(u.Host[:getByteLen(u.Host[:])]),
		Exit: GoExitStatus{
			Termination: int(u.Exit.Termination),
			Exit:        int(u.Exit.Exit),
		},
		Session: int(u.Session),
		Time:    time.Unix(int64(u.Time.Sec), 0),
		Addr:    addrToString(u.Addr),
	}
}

// Integer ip address to string
func addrToString(addr [4]int32) string {
	if addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		return fmt.Sprintf(
			"%d.%d.%d.%d",
			addr[0]&0xFF,
			(addr[0]>>8)&0xFF,
			(addr[0]>>16)&0xFF,
			(addr[0]>>24)&0xFF,
		)
	} else {
		return fmt.Sprintf(
			"%x:%x:%x:%x:%x:%x:%x:%x",
			addr[0]&0xffff,
			(addr[0]>>16)&0xffff,
			addr[1]&0xffff,
			(addr[1]>>16)&0xffff,
			addr[2]&0xffff,
			(addr[2]>>16)&0xffff,
			addr[3]&0xffff,
			(addr[3]>>16)&0xffff,
		)
	}
}

// get byte \0 index
func getByteLen(byteArray []byte) int {
	n := bytes.IndexByte(byteArray[:], 0)
	if n == -1 {
		return 0
	}

	return n
}

func WtmpMetrics() (L []*common.Metric) {
	file, err := os.Open("/var/log/wtmp")
	defer file.Close()
	if err != nil {
		log.Error("open wtmp file failed:", err)
		return
	}
	utmps, err := Read(file)
	if err != nil {
		log.Error("read wtmp file failed:", err)
		return
	}
	for _, gu := range utmps {
		tmp := NewGoUtmp(gu)
		now := time.Now()
		if tmp.Time.After(now.Add(time.Minute * -5)) {
			var m *common.Metric
			m.Name = "kernel.user.login"
			m.Value = 1
			m.Timestamp = tmp.Time.Unix()
			m.Tags = map[string]string{"user": tmp.User, "host": tmp.Host}
			L = append(L, m)
		}
	}
	return
}
