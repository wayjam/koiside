package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"koiside/internal/cli"
)

const protocolVersion = "2025-03-26"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type Server struct {
	deps cli.Deps
	mu   sync.Mutex
	out  io.Writer
}

func NewServer(deps cli.Deps) *Server {
	return &Server{deps: deps}
}

// ServeStdio reads newline-delimited JSON-RPC 2.0 requests from in and writes responses to out.
func ServeStdio(ctx context.Context, in io.Reader, out, errOut io.Writer, deps cli.Deps) error {
	srv := &Server{deps: deps, out: out}
	reader := bufio.NewReader(in)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				srv.handleLine(ctx, []byte(trimmed), errOut)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (s *Server) writeMsg(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.out != nil {
		_, _ = s.out.Write(append(b, '\n'))
	}
}

func (s *Server) handleLine(ctx context.Context, raw []byte, errOut io.Writer) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		s.writeMsg(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: "parse error"},
		})
		return
	}
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		if isNotification {
			return
		}
		s.writeMsg(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    "koiside",
					"version": "0.1.0",
				},
			},
		})
	case "notifications/initialized", "notifications/cancelled":
		return
	case "ping":
		if !isNotification {
			s.writeMsg(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
		}
	case "tools/list":
		if !isNotification {
			s.writeMsg(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{"tools": toolCatalog()},
			})
		}
	case "tools/call":
		if isNotification {
			return
		}
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
			s.writeMsg(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: "invalid tools/call params"},
			})
			return
		}
		res, callErr := s.callTool(ctx, params.Name, params.Arguments, errOut)
		if callErr != nil {
			var ar *cli.ActionRequiredError
			if errors.As(callErr, &ar) {
				payload := map[string]any{
					"status":  "action_required",
					"reason":  ar.Reason,
					"message": ar.Message,
					"next":    ar.Next,
					"details": ar.Details,
				}
				s.writeMsg(rpcResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  toolResult(payload, false),
				})
				return
			}
			s.writeMsg(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  toolResult(map[string]any{"status": "error", "error": callErr.Error()}, true),
			})
			return
		}
		s.writeMsg(rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  toolResult(res, false),
		})
	default:
		if !isNotification {
			s.writeMsg(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
			})
		}
	}
}

func toolResult(payload any, isError bool) map[string]any {
	pretty, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		pretty = []byte(`{"error":"marshal failed"}`)
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(pretty)},
		},
		"structuredContent": payload,
		"isError":           isError,
	}
}

func (s *Server) callTool(ctx context.Context, name string, rawArgs json.RawMessage, errOut io.Writer) (any, error) {
	if len(rawArgs) == 0 {
		rawArgs = []byte("{}")
	}
	switch name {
	case "inspect_ipa":
		var a struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.InspectIPA(a.Path)

	case "prepare_ipa":
		var a cli.PrepareIPARequest
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.PrepareIPA(a)

	case "get_device_status":
		return cli.GetDeviceStatus(s.deps)

	case "list_device_apps":
		var a struct {
			SideloadedOnly bool `json:"sideloaded_only"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.ListDeviceApps(s.deps, a.SideloadedOnly)

	case "transfer_ipa":
		var a struct {
			IPAPath string `json:"ipa_path"`
			Target  string `json:"target"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.TransferIPA(s.deps, a.IPAPath, a.Target)

	case "manage_device_docs":
		var a struct {
			Action     string `json:"action"`
			RemotePath string `json:"remote_path"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.ManageDeviceDocs(s.deps, a.Action, a.RemotePath)

	case "place_pairing_files":
		var a struct {
			ExportPath string `json:"export_path"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.PlacePairing(s.deps, a.ExportPath)

	case "install_ipa":
		var a struct {
			Target           string `json:"target"`
			AutoRevokeOldest bool   `json:"auto_revoke_oldest"`
		}
		if err := json.Unmarshal(rawArgs, &a); err != nil {
			return nil, err
		}
		return cli.InstallIPA(ctx, s.deps, a.Target, a.AutoRevokeOldest, func(pct int, stage string) {
			if errOut != nil {
				_, _ = fmt.Fprintf(errOut, "[koiside-mcp] install %d%%: %s\n", pct, stage)
			}
		})

	case "get_account_quota":
		return cli.GetAccountStatus(ctx, s.deps, true)

	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func toolCatalog() []map[string]any {
	return []map[string]any{
		{
			"name":        "inspect_ipa",
			"description": "Inspect a local .ipa archive (read-only): Bundle ID, version, minimum iOS, architectures, FairPlay encryption status, extensions/Watch components, URL schemes, and findings.",
			"annotations": map[string]any{"readOnlyHint": true},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Local path to the .ipa file."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "prepare_ipa",
			"description": "Preview or export a modified copy of a local .ipa (display name, Bundle ID, localized name, or removing Watch/extension components) without modifying the original archive.",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": false},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"input_path":        map[string]any{"type": "string", "description": "Source .ipa file path."},
					"output_path":       map[string]any{"type": "string", "description": "Destination .ipa file path (must not already exist when preview_only is false)."},
					"display_name":      map[string]any{"type": "string", "description": "Optional new display name."},
					"bundle_id":         map[string]any{"type": "string", "description": "Optional new Bundle ID."},
					"localized_name":    map[string]any{"type": "string", "description": "Optional localized display name for .lproj/InfoPlist.strings."},
					"remove_components": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Archive paths of Watch or extension components to remove."},
					"preview_only":      map[string]any{"type": "boolean", "description": "If true, only compute diff without writing output_path."},
				},
				"required": []string{"input_path"},
			},
		},
		{
			"name":        "get_device_status",
			"description": "Query the connected iPhone over USB (read-only): device info, Developer Mode status, SideStore/LocalDevVPN/LiveContainer detection, /Documents tree, LiveContainer in-container installed apps, and latest SideStore ConsoleLog result.",
			"annotations": map[string]any{"readOnlyHint": true},
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "list_device_apps",
			"description": "List apps installed on the connected iPhone, plus LiveContainer in-container apps.",
			"annotations": map[string]any{"readOnlyHint": true},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"sideloaded_only": map[string]any{"type": "boolean", "description": "Filter system list to developer/sideloaded apps."},
				},
			},
		},
		{
			"name":        "transfer_ipa",
			"description": "Atomically transfer a local .ipa into SideStore or LiveContainer /Documents over USB AFC with SHA-256 verification.",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": false},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ipa_path": map[string]any{"type": "string", "description": "Local path to the .ipa file."},
					"target":   map[string]any{"type": "string", "enum": []string{"auto", "sidestore", "livecontainer"}, "description": "Target app container (default auto)."},
				},
				"required": []string{"ipa_path"},
			},
		},
		{
			"name":        "manage_device_docs",
			"description": "List or delete files inside the connected iPhone's SideStore/LiveContainer /Documents directory.",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action":      map[string]any{"type": "string", "enum": []string{"list", "delete"}},
					"remote_path": map[string]any{"type": "string", "description": "Remote path under /Documents/ (required for delete)."},
				},
				"required": []string{"action"},
			},
		},
		{
			"name":        "place_pairing_files",
			"description": "Generate/reuse RemotePairing + Lockdown pairing files and write them to compatible installed apps (SideStore, LiveContainer, Feather, StikDebug, etc.) or export to disk.",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": false},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"export_path": map[string]any{"type": "string", "description": "Optional local file path to export pairingFile.plist instead of writing to device."},
				},
			},
		},
		{
			"name":        "install_ipa",
			"description": "Sign with the restored Keychain Apple Developer session and install directly over USB (supports 'sidestore', 'sidestore-nightly', 'livecontainer-sidestore', 'livecontainer', or a local .ipa path). Never takes plaintext passwords.",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true},
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target":             map[string]any{"type": "string", "description": "'sidestore', 'sidestore-nightly', 'livecontainer-sidestore', 'livecontainer', or local .ipa path."},
					"auto_revoke_oldest": map[string]any{"type": "boolean", "description": "If true, automatically revoke the oldest development certificate when Apple certificate limit is reached."},
				},
				"required": []string{"target"},
			},
		},
		{
			"name":        "get_account_quota",
			"description": "Inspect the active Apple Developer session (restored from macOS Keychain): team type (free_personal/paid), certificates with has_local_key flag, and 7-day App ID quota & expirations.",
			"annotations": map[string]any{"readOnlyHint": true},
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}
