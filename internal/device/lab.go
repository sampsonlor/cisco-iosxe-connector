package device

import "context"

func (c *Client) Readiness(context.Context, string) (Evidence, error) { return Evidence{}, ErrRead }
