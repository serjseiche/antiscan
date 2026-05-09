package domain

// NetworkList represents a collection of IPv4 subnets
type NetworkList struct {
	IPv4Subnets []string
}

// NewNetworkList creates a new empty network list
func NewNetworkList() *NetworkList {
	return &NetworkList{
		IPv4Subnets: make([]string, 0),
	}
}

// Add adds a subnet to the list
func (nl *NetworkList) Add(subnet string) {
	nl.IPv4Subnets = append(nl.IPv4Subnets, subnet)
}

// IPv4Count returns the number of IPv4 subnets
func (nl *NetworkList) IPv4Count() int {
	return len(nl.IPv4Subnets)
}

// TotalCount returns the total number of subnets
func (nl *NetworkList) TotalCount() int {
	return len(nl.IPv4Subnets)
}
