package shadowsocks

import (
	"bufio"
	"context"
	"io"
	sync "sync"
	"time"

	"github.com/HZ-PRE/XrarCore/common"
	"github.com/HZ-PRE/XrarCore/common/buf"
	"github.com/HZ-PRE/XrarCore/common/errors"
	"github.com/HZ-PRE/XrarCore/common/log"
	"github.com/HZ-PRE/XrarCore/common/net"
	"github.com/HZ-PRE/XrarCore/common/protocol"
	udp_proto "github.com/HZ-PRE/XrarCore/common/protocol/udp"
	"github.com/HZ-PRE/XrarCore/common/session"
	"github.com/HZ-PRE/XrarCore/common/signal"
	"github.com/HZ-PRE/XrarCore/common/task"
	"github.com/HZ-PRE/XrarCore/core"
	"github.com/HZ-PRE/XrarCore/features/policy"
	"github.com/HZ-PRE/XrarCore/features/routing"
	"github.com/HZ-PRE/XrarCore/transport/internet/stat"
	"github.com/HZ-PRE/XrarCore/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	validator     *Validator
	policyManager policy.Manager
	cone          bool
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// NewServer create a new Shadowsocks server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := new(Validator)
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get shadowsocks user").Base(err).AtError()
		}

		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}

	sCtx, cancel := context.WithCancel(ctx)
	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
		cancel:        cancel,
	}
	s.wg.Add(1)
	go s.runPeriodicTask(sCtx)

	return s, nil
}
func (s *Server) runPeriodicTask(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.validator.DetOnUsers()
		case <-ctx.Done():
			return
		}
	}
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

func (s *Server) Network() []net.Network {
	list := s.config.Network
	if len(list) == 0 {
		list = append(list, net.Network_TCP)
	}
	return list
}

type ConnWithReader struct {
	net.Conn
	reader io.Reader
}

func (c *ConnWithReader) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func wrapConn(conn net.Conn, r io.Reader) net.Conn {
	return &ConnWithReader{
		Conn:   conn,
		reader: r,
	}
}

const passwordPrefixMagic byte = 0xAA

func readPasswordPrefix(r *bufio.Reader) string {
	peek, err := r.Peek(2)
	if err != nil || len(peek) != 2 || peek[0] != passwordPrefixMagic {
		return ""
	}

	total := 2 + int(peek[1])
	peekAll, err := r.Peek(total)
	if err != nil || len(peekAll) != total {
		return ""
	}

	header := make([]byte, total)
	if _, err := io.ReadFull(r, header); err != nil {
		return ""
	}
	return string(header[2:])
}

func readPasswordPrefixFromPacket(payload *buf.Buffer) (string, int32, bool) {
	if payload.Len() < 2 || payload.Byte(0) != passwordPrefixMagic {
		return "", 0, false
	}

	length := int32(payload.Byte(1))
	total := int32(2) + length
	if payload.Len() < total {
		return "", 0, false
	}

	return string(payload.BytesRange(2, total)), total, true
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks"
	inbound.CanSpliceCopy = 3
	if network == net.Network_UDP {
		return s.handleUDPPayload(ctx, conn, dispatcher, "")
	}
	if network != net.Network_TCP {
		return errors.New("unknown network: ", network)
	}

	br := bufio.NewReader(conn)
	conn = wrapConn(conn, br)
	return s.handleConnection(ctx, conn, dispatcher, readPasswordPrefix(br))
}

func (s *Server) handleUDPPayload(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher, uid string) error {
	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		request := protocol.RequestHeaderFromContext(ctx)
		if request == nil {
			packet.Payload.Release()
			return
		}

		payload := packet.Payload

		if payload.UDP != nil {
			request = &protocol.RequestHeader{
				User:    request.User,
				Address: payload.UDP.Address,
				Port:    payload.UDP.Port,
			}
		}

		data, err := EncodeUDPPacket(request, payload.Bytes())
		payload.Release()
		if err != nil {
			errors.LogWarningInner(ctx, err, "failed to encode UDP packet")
			return
		}
		defer data.Release()

		conn.Write(data.Bytes())
	})
	defer udpServer.RemoveRay()

	inbound := session.InboundFromContext(ctx)
	var dest *net.Destination
	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		for _, payload := range mpayload {
			validator := s.validator
			if inbound.User != nil {
				validator = new(Validator)
				if err := validator.Add(inbound.User); err != nil {
					payload.Release()
					return errors.New("failed to add shadowsocks user to UDP validator").Base(err)
				}
			}

			decodePayload := payload
			decodeUid := uid
			packetUid, prefixLen, hasPasswordPrefix := readPasswordPrefixFromPacket(payload)
			if hasPasswordPrefix {
				decodePayload = buf.New()
				decodePayload.Write(payload.BytesFrom(prefixLen))
				decodePayload.UDP = payload.UDP
				decodeUid = packetUid
			}

			request, data, err := DecodeUDPPacket(validator, decodePayload, decodeUid)
			if err != nil && hasPasswordPrefix {
				decodePayload.Release()
				decodePayload = payload
				request, data, err = DecodeUDPPacket(validator, decodePayload, uid)
			}
			if err != nil {
				if inbound.Source.IsValid() {
					errors.LogInfoInner(ctx, err, "dropping invalid UDP packet from: ", inbound.Source)
					log.Record(&log.AccessMessage{
						From:   inbound.Source,
						To:     "",
						Status: log.AccessRejected,
						Reason: err,
					})
				}
				decodePayload.Release()
				continue
			}
			if hasPasswordPrefix && decodePayload != payload {
				payload.Release()
				uid = packetUid
			}

			if inbound.User == nil {
				inbound.User = request.User
			}

			destination := request.Destination()

			currentPacketCtx := ctx
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     destination,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  request.User.Email,
				})
			}
			errors.LogInfo(ctx, "tunnelling request to ", destination)

			if data.UDP == nil {
				data.UDP = &destination
			}

			if !s.cone || dest == nil {
				dest = &destination
			}

			currentPacketCtx = protocol.ContextWithRequestHeader(currentPacketCtx, request)
			udpServer.Dispatch(currentPacketCtx, *dest, data)
		}
	}

	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher, uid string) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
	request, bodyReader, err := ReadTCPSession(s.validator, &bufferedReader, uid)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return errors.New("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	conn.SetReadDeadline(time.Time{})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = request.User

	dest := request.Destination()
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to ", dest)

	sessionPolicy = s.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		responseWriter, err := WriteTCPResponse(request, bufferedWriter)
		if err != nil {
			return errors.New("failed to write response").Base(err)
		}

		{
			payload, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if err := responseWriter.WriteMultiBuffer(payload); err != nil {
				return err
			}
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		if err := buf.Copy(link.Reader, responseWriter, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(bodyReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
