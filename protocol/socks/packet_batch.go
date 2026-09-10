package socks

import (
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ N.PacketBatchWriteCreator = (*AssociatePacketConn)(nil)
	_ N.PacketBatchWriteCreator = (*LazyAssociatePacketConn)(nil)
)

func (c *AssociatePacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	writer, created := bufio.CreateConnectedPacketBatchWriter(bufio.NewUnbindPacketConn(c.conn))
	if !created {
		return nil, false
	}
	return &associatePacketBatchWriter{writer}, true
}

type associatePacketBatchWriter struct {
	writer N.ConnectedPacketBatchWriter
}

func (w *associatePacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	for index, buffer := range buffers {
		destination := destinations[index]
		headerLen := 3 + M.SocksaddrSerializer.AddrPortLen(destination)
		if buffer.Start() < headerLen {
			newBuffer := buf.NewSize(headerLen + buffer.Len())
			newBuffer.Resize(headerLen, 0)
			common.Must1(newBuffer.Write(buffer.Bytes()))
			buffer.Release()
			buffer = newBuffer
			buffers[index] = buffer
		}
		header := buf.With(buffer.ExtendHeader(headerLen))
		common.Must(header.WriteZeroN(3))
		err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	return w.writer.WriteConnectedPacketBatch(buffers)
}

func (c *LazyAssociatePacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	writer, created := c.AssociatePacketConn.CreatePacketBatchWriter()
	if !created {
		return nil, false
	}
	return &lazyAssociatePacketBatchWriter{c, writer}, true
}

type lazyAssociatePacketBatchWriter struct {
	conn   *LazyAssociatePacketConn
	writer N.PacketBatchWriter
}

func (w *lazyAssociatePacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	err := w.conn.HandshakeSuccess()
	if err != nil {
		buf.ReleaseMulti(buffers)
		return err
	}
	return w.writer.WritePacketBatch(buffers, destinations)
}
