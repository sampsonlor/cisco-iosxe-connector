package device

import "context"

const (
	ReadClock          Operation = "read-clock"
	ReadNTP            Operation = "read-ntp-status"
	ReadPrivilege      Operation = "read-privilege"
	ReadProtocolConfig Operation = "read-protocol-config"
)

// Readiness adds only fixed, non-mutating lab observations. It never probes a
// write command to discover permissions and never enables a protocol.
func (c *Client) Readiness(ctx context.Context, id string) (e Evidence, err error) {
	t, ok := c.targets[id]
	if !ok || t.CLI == nil {
		return e, ErrPolicy
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	e.Raw = map[Operation][]byte{}
	e.Capabilities = map[Operation]Capability{}
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			e.Raw = nil
			e.Complete = false
		}
	}()
	err = c.readCLIOperations(ctx, t, &e, []Operation{ReadClock, ReadNTP, ReadPrivilege, ReadProtocolConfig})
	e.Complete = err == nil
	return e, err
}
