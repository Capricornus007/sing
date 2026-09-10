package socks

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks/socks5"

	"github.com/stretchr/testify/require"
)

func TestAssociatePacketBatchHeaders(t *testing.T) {
	t.Parallel()
	for _, headroom := range []int{0, 3 + M.MaxSocksaddrLength} {
		t.Run(map[bool]string{true: "in_place", false: "copy"}[headroom > 0], func(t *testing.T) {
			t.Parallel()
			upstream := &recordConnectedPacketBatchWriter{}
			writer := &associatePacketBatchWriter{upstream}
			payloads := []string{"ipv4", "ipv6", "", "domain"}
			destinations := []M.Socksaddr{
				M.ParseSocksaddr("192.0.2.1:1000"),
				M.ParseSocksaddr("[2001:db8::1]:2000"),
				M.ParseSocksaddr("empty.example:3000"),
				M.ParseSocksaddr("example.org:4000"),
			}
			buffers := socksBatchBuffers(headroom, payloads...)
			originalBuffers := append([]*buf.Buffer(nil), buffers...)
			require.NoError(t, writer.WritePacketBatch(buffers, destinations))
			require.Equal(t, 1, upstream.calls)
			for index, packet := range upstream.packets {
				assertSocksBatchPacket(t, packet, destinations[index], payloads[index])
				require.Zero(t, originalBuffers[index].Cap())
				require.Zero(t, buffers[index].Cap())
				if headroom > 0 {
					require.Same(t, originalBuffers[index], buffers[index])
				} else {
					require.NotSame(t, originalBuffers[index], buffers[index])
				}
			}
		})
	}
}

func TestAssociatePacketBatchErrors(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name         string
		payloads     []string
		destinations []M.Socksaddr
		writeErr     error
	}{
		{name: "empty"},
		{name: "mismatch", payloads: []string{"a", "b"}, destinations: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:53")}},
		{name: "invalid_address", payloads: []string{"a", "b", "c"}, destinations: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:53"), {}, {}}},
		{name: "long_domain", payloads: []string{"a", "b"}, destinations: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:53"), {Fqdn: strings.Repeat("a", 256), Port: 53}}},
		{name: "write_error", payloads: []string{"a"}, destinations: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:53")}, writeErr: io.ErrClosedPipe},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			upstream := &recordConnectedPacketBatchWriter{err: testCase.writeErr}
			writer := &associatePacketBatchWriter{upstream}
			buffers := socksBatchBuffers(0, testCase.payloads...)
			originalBuffers := append([]*buf.Buffer(nil), buffers...)
			err := writer.WritePacketBatch(buffers, testCase.destinations)
			require.Error(t, err)
			if testCase.writeErr != nil {
				require.ErrorIs(t, err, testCase.writeErr)
				require.Equal(t, 1, upstream.calls)
			} else {
				require.Zero(t, upstream.calls)
			}
			for index, buffer := range buffers {
				require.Zero(t, buffer.Cap())
				require.Zero(t, originalBuffers[index].Cap())
			}
		})
	}
}

func TestAssociatePacketBatchUDP(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"associate", "vectorised", "lazy"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			server, client := socksBatchUDPPair(t)
			control := &recordHandshakeConn{}
			var conn N.PacketWriter
			switch kind {
			case "associate":
				conn = NewAssociatePacketConn(client, M.Socksaddr{}, nil)
			case "vectorised":
				conn = NewVectorisedAssociateConn(client, bufio.NewVectorisedWriter(client), M.Socksaddr{}, nil)
			case "lazy":
				conn = NewLazyAssociatePacketConn(client, control)
			}
			writer, created := bufio.CreatePacketBatchWriter(conn)
			require.Zero(t, control.writes, "capability discovery must not send the handshake")
			requireSocksBatchBackend(t, created)
			_, connectedCreated := bufio.CreateConnectedPacketBatchWriter(conn)
			require.False(t, connectedCreated, "SOCKS destinations must not be discarded")
			destination := M.ParseSocksaddr("example.org:53")
			for _, payload := range []string{"first", "second"} {
				require.NoError(t, writer.WritePacketBatch(socksBatchBuffers(0, payload, ""), []M.Socksaddr{destination, destination}))
				for _, expected := range []string{payload, ""} {
					packet := make([]byte, 512)
					n, _, err := server.ReadFromUDP(packet)
					require.NoError(t, err)
					assertSocksBatchPacket(t, packet[:n], destination, expected)
				}
			}
			if kind == "lazy" {
				require.Equal(t, 1, control.writes)
				response, err := socks5.ReadResponse(bytes.NewReader(control.data.Bytes()))
				require.NoError(t, err)
				require.Equal(t, socks5.ReplyCodeSuccess, response.ReplyCode)
				require.Equal(t, M.SocksaddrFromNet(client.LocalAddr()).Unwrap(), response.Bind)
			}
		})
	}
}

func TestLazyAssociatePacketBatchHandshakeFailure(t *testing.T) {
	t.Parallel()
	server, client := socksBatchUDPPair(t)
	control := &recordHandshakeConn{err: io.ErrClosedPipe}
	conn := NewLazyAssociatePacketConn(client, control)
	writer, created := bufio.CreatePacketBatchWriter(conn)
	requireSocksBatchBackend(t, created)
	require.Zero(t, control.writes)
	require.ErrorIs(t, writer.WritePacketBatch(nil, nil), os.ErrInvalid)
	require.Zero(t, control.writes)
	buffers := socksBatchBuffers(0, "a", "b")
	destination := M.ParseSocksaddr("192.0.2.1:53")
	require.ErrorIs(t, writer.WritePacketBatch(buffers, []M.Socksaddr{destination, destination}), io.ErrClosedPipe)
	require.Equal(t, 1, control.writes)
	for _, buffer := range buffers {
		require.Zero(t, buffer.Cap())
	}
	require.NoError(t, server.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, _, err := server.ReadFromUDP(make([]byte, 512))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestAssociatePacketBatchUnavailable(t *testing.T) {
	t.Parallel()
	left, right := net.Pipe()
	t.Cleanup(func() { left.Close() })
	t.Cleanup(func() { right.Close() })
	_, client := socksBatchUDPPair(t)
	for _, conn := range []net.Conn{left, &opaqueSocksConn{client}} {
		writer, created := bufio.CreatePacketBatchWriter(NewAssociatePacketConn(conn, M.Socksaddr{}, nil))
		require.False(t, created)
		require.Nil(t, writer)
		control := &recordHandshakeConn{}
		writer, created = bufio.CreatePacketBatchWriter(NewLazyAssociatePacketConn(conn, control))
		require.False(t, created)
		require.Nil(t, writer)
		require.Zero(t, control.writes)
	}
}

func TestCopyPacketSOCKSBatchWithNATAndCounters(t *testing.T) {
	t.Parallel()
	server, client := socksBatchUDPPair(t)
	conn := NewAssociatePacketConn(client, M.Socksaddr{}, nil)
	_, created := bufio.CreatePacketBatchWriter(conn)
	requireSocksBatchBackend(t, created)
	origin := M.ParseSocksaddr("192.0.2.1:53")
	destination := M.ParseSocksaddr("192.0.2.2:53")
	natConn := bufio.NewNATPacketConn(conn, origin, destination)
	var byteCount, packetCount atomic.Int64
	counterConn := bufio.NewInt64CounterPacketConn(natConn, nil, nil, []*atomic.Int64{&byteCount}, []*atomic.Int64{&packetCount})
	source := &socksPacketBatchReader{destination: destination}
	n, err := bufio.CopyPacket(counterConn, source)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, int64(3), n)
	require.True(t, source.usedBatch)
	require.Equal(t, int64(3), byteCount.Load())
	require.Equal(t, int64(2), packetCount.Load())
	for _, payload := range []string{"a", "bc"} {
		packet := make([]byte, 512)
		n, _, err := server.ReadFromUDP(packet)
		require.NoError(t, err)
		assertSocksBatchPacket(t, packet[:n], origin, payload)
	}
}

type recordConnectedPacketBatchWriter struct {
	packets [][]byte
	calls   int
	err     error
}

func (w *recordConnectedPacketBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.calls++
	for _, buffer := range buffers {
		w.packets = append(w.packets, bytes.Clone(buffer.Bytes()))
	}
	return w.err
}

type recordHandshakeConn struct {
	net.Conn
	data   bytes.Buffer
	writes int
	err    error
}

func (c *recordHandshakeConn) Write(data []byte) (int, error) {
	c.writes++
	if c.err != nil {
		return 0, c.err
	}
	return c.data.Write(data)
}

type opaqueSocksConn struct {
	net.Conn
}

func (c *opaqueSocksConn) Upstream() any {
	return c.Conn
}

type socksPacketBatchReader struct {
	destination M.Socksaddr
	usedBatch   bool
}

func (r *socksPacketBatchReader) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errors.New("unexpected single packet read")
}

func (r *socksPacketBatchReader) InitializeReadWaiter(N.ReadWaitOptions) bool {
	return false
}

func (r *socksPacketBatchReader) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	if r.usedBatch {
		return nil, nil, io.EOF
	}
	r.usedBatch = true
	return socksBatchBuffers(0, "a", "bc"), []M.Socksaddr{r.destination, r.destination}, nil
}

func socksBatchBuffers(headroom int, payloads ...string) []*buf.Buffer {
	buffers := make([]*buf.Buffer, len(payloads))
	for index, payload := range payloads {
		buffer := buf.NewSize(max(1, headroom+len(payload)))
		buffer.Resize(headroom, 0)
		_, _ = buffer.WriteString(payload)
		buffers[index] = buffer
	}
	return buffers
}

func assertSocksBatchPacket(t *testing.T, packet []byte, destination M.Socksaddr, payload string) {
	t.Helper()
	require.GreaterOrEqual(t, len(packet), 3)
	require.Equal(t, []byte{0, 0, 0}, packet[:3])
	reader := bytes.NewReader(packet[3:])
	actualDestination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	require.NoError(t, err)
	require.Equal(t, destination, actualDestination)
	actualPayload, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, payload, string(actualPayload))
}

func socksBatchUDPPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, server.SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	return server, client
}

func requireSocksBatchBackend(t *testing.T, created bool) {
	t.Helper()
	switch runtime.GOOS {
	case "linux", "darwin", "netbsd", "android", "ios":
		require.True(t, created)
	default:
		require.False(t, created)
		t.Skip("connected packet batch backend is not available")
	}
}
