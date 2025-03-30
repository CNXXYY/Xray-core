package internet

import (
	"context"
	"math/rand"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
)

var effectiveSystemDialer SystemDialer = &DefaultSystemDialer{}

type SystemDialer interface {
	Dial(ctx context.Context, source net.Address, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
	DestIpAddress() net.IP
}

type DefaultSystemDialer struct {
	controllers []control.Func
	dns         dns.Client
	obm         outbound.Manager
}

func resolveSrcAddr(network net.Network, src net.Address) net.Addr {
	if src == nil || src == net.AnyIP {
		return nil
	}

	if network == net.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: 0,
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: 0,
	}
}

func hasBindAddr(sockopt *SocketConfig) bool {
	return sockopt != nil && len(sockopt.BindAddress) > 0 && sockopt.BindPort > 0
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	errors.LogDebug(ctx, "dialing to "+dest.String())

	goStdKeepAlive := time.Duration(0)
	if sockopt != nil && (sockopt.TcpKeepAliveInterval != 0 || sockopt.TcpKeepAliveIdle != 0) {
		goStdKeepAlive = time.Duration(-1)
	}
	dialer := &net.Dialer{
		Timeout:   time.Second * 16,
		LocalAddr: resolveSrcAddr(dest.Network, src),
		KeepAlive: goStdKeepAlive,
	}

	if sockopt != nil || len(d.controllers) > 0 {
		if sockopt != nil && sockopt.TcpMptcp && dest.Network != net.Network_UDP {
			dialer.SetMultipathTCP(true)
		}
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			for _, ctl := range d.controllers {
				if err := ctl(network, address, c); err != nil {
					errors.LogInfoInner(ctx, err, "failed to apply external controller")
				}
			}
			return c.Control(func(fd uintptr) {
				if sockopt != nil {
					if err := applyOutboundSocketOptions(network, address, fd, sockopt); err != nil {
						errors.LogInfoInner(ctx, err, "failed to apply socket options")
					}
					if dest.Network == net.Network_UDP && hasBindAddr(sockopt) {
						if err := bindAddr(fd, sockopt.BindAddress, sockopt.BindPort); err != nil {
							errors.LogInfoInner(ctx, err, "failed to bind source address to ", sockopt.BindAddress)
						}
					}
				}
			})
		}
	}

	return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func (d *DefaultSystemDialer) DestIpAddress() net.IP {
	return nil
}

type SystemDialerAdapter interface {
	Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
	adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
	return &SimpleSystemDialer{
		adapter: dialer,
	}
}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

func (d *SimpleSystemDialer) DestIpAddress() net.IP {
	return nil
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// xray:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
	if dialer == nil {
		dialer = &DefaultSystemDialer{}
	}
	effectiveSystemDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// It only works when effective dialer is the default dialer.
//
// xray:api:beta
func RegisterDialerController(ctl control.Func) error {
	if ctl == nil {
		return errors.New("nil listener controller")
	}

	dialer, ok := effectiveSystemDialer.(*DefaultSystemDialer)
	if !ok {
		return errors.New("RegisterListenerController not supported in custom dialer")
	}

	dialer.controllers = append(dialer.controllers, ctl)
	return nil
}

type FakePacketConn struct {
	net.Conn
}

func (c *FakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *FakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *FakePacketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
		Port: rand.Intn(65536),
	}
}

func (c *FakePacketConn) SetReadBuffer(bytes int) error {
	// do nothing, this function is only there to suppress quic-go printing
	// random warnings about UDP buffers to stdout
	return nil
}
