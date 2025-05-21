package joinPlugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/joinPlugin/pb"
	"google.golang.org/grpc"
)

type Addr struct {
	Scheme string
	Host   string
	Port   uint16
}

type Join interface {
	Candidates(map[string]string) ([]Addr, error)
}

type JoinPlugin struct {
	plugin.NetRPCUnsupportedPlugin

	Impl Join
}

type GRPCClient struct {
	client pb.JoinClient
}

type GRPCServer struct {
	pb.UnimplementedJoinServer

	Impl Join
}

func (g *GRPCServer) Candidates(ctx context.Context, args *pb.CandidateArgs) (*pb.Candidates, error) {
	// TODO: Should Candidates() return []*pb.Candidate directly?
	v, err := g.Impl.Candidates(args.Config)
	if err != nil {
		return nil, err
	}
	candidates := make([]*pb.Candidate, 0, len(v))
	for _, c := range v {
		candidate := &pb.Candidate{Scheme: c.Scheme, Host: c.Host, Port: uint32(c.Port)}
		candidates = append(candidates, candidate)
	}
	return &pb.Candidates{Candidates: candidates}, err
}

func (j *JoinPlugin) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: pb.NewJoinClient(c)}, nil
}

func (j *JoinPlugin) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterJoinServer(s, &GRPCServer{Impl: j.Impl})
	return nil
}

var (
	_ plugin.Plugin     = &JoinPlugin{}
	_ plugin.GRPCPlugin = &JoinPlugin{}
)
