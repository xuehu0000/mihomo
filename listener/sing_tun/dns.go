package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
	for _, addrPort := range h.DnsAddrPorts {
		if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
			return true
		}
	}
	return false
}

func (h *ListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	// Dirty hack v2: TUN 入站写死 2h keepalive 当僵尸收割机,不吃全局配置。
	// 原理: sing-tun 的 system 栈用普通 net.ListenConfig 接受 TUN 入站 TCP,
	// 全局 keepalive 配置到不了这些 socket(默认是 Go 的 15s/15s)。
	// 这里直接写死 Idle=7200s / Interval=75s / Count=9:2h 无流量才开始探测,
	// 9 次无应答(约 2.2h)判定死亡,由内核回收——7x24 无人值守不堆僵尸。
	// 类型断言失败(gvisor/mipstack 用户态连接)则静默跳过,所以实际只影响
	// system 栈(含 mixed 的 TCP 一半)。
	if tcp, ok := conn.(keepalive.TCPConn); ok && tcp != nil {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   true,
			Idle:     7200 * time.Second,
			Interval: 75 * time.Second,
			Count:    9,
		})
	}
	if h.ShouldHijackDns(metadata.Destination.AddrPort()) {
		log.Debugln("[DNS] hijack tcp:%s", metadata.Destination.String())
		return resolver.RelayDnsConn(ctx, conn, resolver.DefaultDnsReadTimeout)
	}
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (h *ListenerHandler) NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn network.PacketConn) network.PacketWriter) {
	if h.ShouldHijackDns(metadata.Destination.AddrPort()) {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		writer := init(nil)
		rwOptions := network.ReadWaitOptions{
			FrontHeadroom: network.CalculateFrontHeadroom(writer),
			RearHeadroom:  network.CalculateRearHeadroom(writer),
			MTU:           resolver.SafeDnsPacketSize,
		}
		go relayDnsPacket(ctx, buffer, rwOptions, metadata.Destination, nil, &writer)
		return
	}
	h.ListenerHandler.NewPacket(ctx, key, buffer, metadata, init)
}

func (h *ListenerHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	if h.ShouldHijackDns(metadata.Destination.AddrPort()) {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		defer func() { _ = conn.Close() }()
		mutex := sync.Mutex{}
		var writer network.PacketWriter = conn // a new interface to set nil in defer
		defer func() {
			mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
			defer mutex.Unlock()
			writer = nil
		}()
		rwOptions := network.ReadWaitOptions{
			FrontHeadroom: network.CalculateFrontHeadroom(conn),
			RearHeadroom:  network.CalculateRearHeadroom(conn),
			MTU:           resolver.SafeDnsPacketSize,
		}
		readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
		if isReadWaiter {
			readWaiter.InitializeReadWaiter(rwOptions)
		}
		for {
			var (
				readBuff *buf.Buffer
				dest     M.Socksaddr
				err      error
			)
			_ = conn.SetReadDeadline(time.Now().Add(resolver.DefaultDnsReadTimeout))
			readBuff = nil // clear last loop status, avoid repeat release
			if isReadWaiter {
				readBuff, dest, err = readWaiter.WaitReadPacket()
			} else {
				readBuff = rwOptions.NewPacketBuffer()
				dest, err = conn.ReadPacket(readBuff)
				if readBuff != nil {
					rwOptions.PostReturn(readBuff)
				}
			}
			if err != nil {
				if readBuff != nil {
					readBuff.Release()
				}
				if sing.ShouldIgnorePacketError(err) {
					break
				}
				return err
			}
			go relayDnsPacket(ctx, readBuff, rwOptions, dest, &mutex, &writer)
		}
		return nil
	}
	return h.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}

func relayDnsPacket(ctx context.Context, readBuff *buf.Buffer, rwOptions network.ReadWaitOptions, dest M.Socksaddr, mutex *sync.Mutex, writer *network.PacketWriter) {
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDnsRelayTimeout)
	defer cancel()
	inData := readBuff.Bytes()
	writeBuff := readBuff
	writeBuff.Resize(writeBuff.Start(), 0)
	if len(writeBuff.FreeBytes()) < resolver.SafeDnsPacketSize { // only create a new buffer when space don't enough
		writeBuff = rwOptions.NewPacketBuffer()
	}
	msg, err := resolver.RelayDnsPacket(ctx, inData, writeBuff.FreeBytes())
	if writeBuff != readBuff {
		readBuff.Release()
	}
	if err != nil {
		writeBuff.Release()
		return
	}
	writeBuff.Truncate(len(msg))
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	conn := *writer
	if conn == nil {
		writeBuff.Release()
		return
	}
	err = conn.WritePacket(writeBuff, dest) // WritePacket will release writeBuff
	if err != nil {
		writeBuff.Release()
		return
	}
}

func (h *ListenerHandler) TypeMutation(typ C.Type) *ListenerHandler {
	handle := *h
	handle.ListenerHandler = h.ListenerHandler.TypeMutation(typ)
	return &handle
}
