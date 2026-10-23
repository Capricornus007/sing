package network

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// 這支測的是「同一個 PacketBuffer 被歸還兩次」會怎樣。
//
// 由來（全部有提交可查）：sing-box 的 UDP 路由裡，同一批封包緩衝被處理兩遍——
// 先一段內聯迴圈 Put、接著又呼叫 helper 再 Put 一次。第二次 Put 時那塊已經被
// `*packet = PacketBuffer{}` 清成零值，於是 `bufio.NewCachedPacketConn` 拿 nil Buffer
// 去 IncRef → 空指標 panic → Go 執行期自我 SIGABRT（裝置端 102 筆 tombstone 全長成
// 「兩格 unknown、沒有 Abort message」就是這個）。
// 10-05 修過（d468ba640）、10-09 吃 upstream/testing 合併又復發、10-10 再修（c1dfeafd）。
// 所以約束放在**型別這層**：雙重歸還必須是無操作，而且要能被測試抓出來。
func TestPutPacketBufferTwiceIsNoop(t *testing.T) {
	t.Parallel()
	packet := NewPacketBuffer()
	packet.Buffer = buf.New()
	packet.Buffer.WriteByte(0x7f)

	PutPacketBuffer(packet)
	PutPacketBuffer(packet) // 第二次：必須被忽略，不能讓同一指針進池兩份

	first := NewPacketBuffer()
	second := NewPacketBuffer()
	if first == second {
		t.Fatal("雙重歸還把同一個指針塞進了池兩次：兩個 NewPacketBuffer 拿到同一塊")
	}
	if first == packet && second == packet {
		t.Fatal("同上，兩個都是那塊被回兩次的緩衝")
	}
}

// 歸還過的緩衝不能再被当成有效資料使用：Put 必須把 Buffer 與 Destination 清掉，
// 這樣呼叫端就算误用，看到的也是明顯的空對象，而不是還帶著上一手內容的實例。
func TestPutPacketBufferClearsFields(t *testing.T) {
	t.Parallel()
	packet := NewPacketBuffer()
	packet.Buffer = buf.New()
	packet.Destination = M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 53)

	PutPacketBuffer(packet)
	if packet.Buffer != nil {
		t.Fatal("PutPacketBuffer 之後 Buffer 還在：池裡會帶著上一手的資料")
	}
	if packet.Destination != (M.Socksaddr{}) {
		t.Fatalf("PutPacketBuffer 之後 Destination 還在：%s", packet.Destination.String())
	}
}
