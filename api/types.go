package api

type PType string

const (
	Role   PType = "g"
	Group  PType = "g2"
	Policy PType = "p"
)

// +gogo:genproto=true
type Subject struct {
	PType PType  `json:"ptype" protobuf:"bytes,1,opt,name=ptype,proto3,casttype=PType"`
	User  string `json:"user" protobuf:"bytes,2,opt,name=user,proto3"`
	Group string `json:"group" protobuf:"bytes,3,opt,name=group,proto3"`
}
