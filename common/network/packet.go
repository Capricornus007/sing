package network

import (
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type PacketBuffer struct {
	Buffer      *buf.Buffer
	Destination M.Socksaddr
	// returned 是「這塊已經歸還過」的標記，只在下面兩個函式裡用。
	//
	// 為什麼要有它：`PutPacketBuffer` 原本無條件把指針塞回 sync.Pool，
	// 同一塊被歸還兩次，池裡就會出現**兩個同樣的指針**，之後兩個 Get 拿到同一個
	// PacketBuffer —— 表現是隨機資料錯亂，或先被清零那個拿到 nil 再 IncRef 直接崩。
	// 這不是假想：sing-box 的 UDP 路徑 10-05 修過一次（d468ba640），10-09 吃
	// upstream/testing 合併時又把那段內聯迴圈撿回來（67a13e407 → 復發 6 筆 SIGABRT），
	// 10-10 才再修（c1dfeafd）。既然「吃上游就會復發」，就在**型別這一層**擋掉，
	// 讓它變成無害，而不是等下一次崩潰再搶 time。
	returned bool
}

var packetPool = sync.Pool{
	New: func() any {
		return new(PacketBuffer)
	},
}

func NewPacketBuffer() *PacketBuffer {
	packet := packetPool.Get().(*PacketBuffer)
	packet.returned = false
	return packet
}

func PutPacketBuffer(packet *PacketBuffer) {
	if packet == nil || packet.returned {
		return
	}
	packet.returned = true
	packet.Buffer = nil
	packet.Destination = M.Socksaddr{}
	packetPool.Put(packet)
}

func ReleaseMultiPacketBuffer(packetBuffers []*PacketBuffer) {
	for _, packet := range packetBuffers {
		if packet == nil {
			continue
		}
		if packet.Buffer != nil {
			packet.Buffer.Release()
		}
		PutPacketBuffer(packet)
	}
}
