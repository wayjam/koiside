package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"koiside/internal/appstore"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	if strings.TrimSpace(v) != "" {
		*s = append(*s, strings.TrimSpace(v))
	}
	return nil
}

// IsCommand reports whether arg[0] routes to the headless CLI/MCP instead of the GUI window.
func IsCommand(arg string) bool {
	switch arg {
	case "ipa", "device", "transfer", "pairing", "install", "account", "store", "mcp", "help", "-h", "--help", "version":
		return true
	default:
		return false
	}
}

// Run executes one CLI invocation and returns a POSIX exit code.
func Run(ctx context.Context, args []string, deps Deps, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return ExitOK
	}
	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	case "version":
		fmt.Fprintln(stdout, "KoiSide 0.1.0")
		return ExitOK
	case "ipa":
		return runIPA(args[1:], stdout, stderr)
	case "device":
		return runDevice(args[1:], deps, stdout, stderr)
	case "transfer":
		return runTransfer(args[1:], deps, stdout, stderr)
	case "pairing":
		return runPairing(args[1:], deps, stdout, stderr)
	case "install":
		return runInstall(ctx, args[1:], deps, stdout, stderr)
	case "account":
		return runAccount(ctx, args[1:], deps, stdout, stderr)
	case "store":
		return runStore(ctx, args[1:], deps, stdout, stderr)
	default:
		printUsage(stderr)
		return ExitUsage
	}
}

func runIPA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: koiside ipa <inspect|preview|export> ...")
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "inspect":
		fs := flag.NewFlagSet("ipa inspect", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside ipa inspect <path.ipa> [--json]")
			return ExitUsage
		}
		res, err := InspectIPA(pos[0])
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "%s (%s · v%s)\nSHA-256: %s\nComponents: %d, Mach-Os: %d, Findings: %d\n",
			res.DisplayName, res.BundleID, res.Version, res.SHA256, len(res.Components), len(res.MachOs), len(res.Findings))
		return ExitOK

	case "preview", "export":
		fs := flag.NewFlagSet("ipa "+sub, flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		name := fs.String("name", "", "new display name")
		bundleID := fs.String("bundle-id", "", "new bundle identifier")
		locName := fs.String("localized-name", "", "new localized display name")
		outPath := fs.String("o", "", "output IPA path")
		var removes stringSliceFlag
		fs.Var(&removes, "remove", "component archive path to remove (repeatable)")
		rest, pos := extractPositional(rest, map[string]bool{
			"name": true, "bundle-id": true, "localized-name": true, "o": true, "remove": true,
		})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintf(stderr, "usage: koiside ipa %s <path.ipa> [--bundle-id ...] [--name ...] [--remove ...] [-o out.ipa] [--json]\n", sub)
			return ExitUsage
		}
		res, err := PrepareIPA(PrepareIPARequest{
			InputPath:     pos[0],
			OutputPath:    *outPath,
			DisplayName:   *name,
			BundleID:      *bundleID,
			LocalizedName: *locName,
			Remove:        removes,
			PreviewOnly:   sub == "preview",
		})
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		if res.Exported != nil {
			fmt.Fprintf(stdout, "Exported: %s (SHA-256: %s)\n", res.Exported.OutputPath, res.Exported.OutputSHA256)
		} else {
			fmt.Fprintf(stdout, "Preview changes: %d, findings: %d\n", len(res.Diff.Items), len(res.Diff.Findings))
		}
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown ipa subcommand %q\n", sub)
		return ExitUsage
	}
}

func runDevice(args []string, deps Deps, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: koiside device <status|apps|devmode|docs> ...")
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		fs := flag.NewFlagSet("device status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		res, err := GetDeviceStatus(deps)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		if !res.Connected {
			fmt.Fprintln(stdout, "No iPhone connected")
			return ExitOK
		}
		fmt.Fprintf(stdout, "Device: %s (%s · iOS %s)\nDeveloperModeKnown: %v, Enabled: %v, USBVerified: %v, LiveContainerApps: %d\n",
			res.Info.Name, res.Device.UDID, res.Info.Version, res.DeveloperModeKnown, res.DeveloperModeEnabled, res.USBVerified, len(res.LiveContainerApps))
		return ExitOK

	case "apps":
		fs := flag.NewFlagSet("device apps", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		sideloaded := fs.Bool("sideloaded", false, "only sideloaded/dev apps")
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		res, err := ListDeviceApps(deps, *sideloaded)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		for _, a := range res.Apps {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", a.Name, a.BundleID, a.Version)
		}
		return ExitOK

	case "devmode":
		if len(rest) == 0 || rest[0] != "enable" {
			fmt.Fprintln(stderr, "usage: koiside device devmode enable [--json]")
			return ExitUsage
		}
		fs := flag.NewFlagSet("device devmode enable", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(rest[1:]); err != nil {
			return ExitUsage
		}
		res, err := EnableDeveloperMode(deps)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintln(stdout, res["message"])
		return ExitOK

	case "docs":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: koiside device docs <ls|rm> ...")
			return ExitUsage
		}
		docSub, docRest := rest[0], rest[1:]
		fs := flag.NewFlagSet("device docs "+docSub, flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		docRest, pos := extractPositional(docRest, map[string]bool{})
		if err := fs.Parse(docRest); err != nil {
			return ExitUsage
		}
		switch docSub {
		case "ls":
			res, err := ManageDeviceDocs(deps, "list", "")
			if err != nil {
				return emitErr(*asJSON, err, stdout, stderr)
			}
			if *asJSON {
				return emitJSON(stdout, res)
			}
			for _, e := range res.Entries {
				fmt.Fprintf(stdout, "%s\tdir=%v\t%d\n", e.Path, e.IsDir, e.Size)
			}
			return ExitOK
		case "rm":
			if len(pos) < 1 {
				fmt.Fprintln(stderr, "usage: koiside device docs rm </Documents/...> [--json]")
				return ExitUsage
			}
			res, err := ManageDeviceDocs(deps, "delete", pos[0])
			if err != nil {
				return emitErr(*asJSON, err, stdout, stderr)
			}
			if *asJSON {
				return emitJSON(stdout, res)
			}
			fmt.Fprintf(stdout, "Deleted %s (%s)\n", res.DeletedPath, res.DocsBundleID)
			return ExitOK
		default:
			fmt.Fprintf(stderr, "unknown docs subcommand %q\n", docSub)
			return ExitUsage
		}
	default:
		fmt.Fprintf(stderr, "unknown device subcommand %q\n", sub)
		return ExitUsage
	}
}

func runTransfer(args []string, deps Deps, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("transfer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	to := fs.String("to", "auto", "target container: auto, sidestore, or livecontainer")
	rest, pos := extractPositional(args, map[string]bool{"to": true})
	if err := fs.Parse(rest); err != nil {
		return ExitUsage
	}
	if len(pos) < 1 {
		fmt.Fprintln(stderr, "usage: koiside transfer <path.ipa> [--to auto|sidestore|livecontainer] [--json]")
		return ExitUsage
	}
	res, err := TransferIPA(deps, pos[0], *to)
	if err != nil {
		return emitErr(*asJSON, err, stdout, stderr)
	}
	if *asJSON {
		return emitJSON(stdout, res)
	}
	fmt.Fprintf(stdout, "Transferred to %s:%s (SHA-256: %s)\n", res.TargetBundleID, res.RemotePath, res.SHA256)
	return ExitOK
}

func runPairing(args []string, deps Deps, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "place" {
		fmt.Fprintln(stderr, "usage: koiside pairing place [--export path] [--json]")
		return ExitUsage
	}
	fs := flag.NewFlagSet("pairing place", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	exportPath := fs.String("export", "", "export pairing plist locally instead of placing into apps")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	res, err := PlacePairing(deps, *exportPath)
	if err != nil {
		return emitErr(*asJSON, err, stdout, stderr)
	}
	if *asJSON {
		return emitJSON(stdout, res)
	}
	if res.ExportPath != "" {
		fmt.Fprintf(stdout, "Exported pairing file to %s\n", res.ExportPath)
	} else {
		fmt.Fprintf(stdout, "Placed pairing files in: %s\n", strings.Join(res.Placed, ", "))
	}
	return ExitOK
}

func runInstall(ctx context.Context, args []string, deps Deps, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	autoRevoke := fs.Bool("auto-revoke-oldest", false, "automatically revoke oldest certificate if Apple limit is reached")
	rest, pos := extractPositional(args, map[string]bool{})
	if err := fs.Parse(rest); err != nil {
		return ExitUsage
	}
	if len(pos) < 1 {
		fmt.Fprintln(stderr, "usage: koiside install <sidestore|sidestore-nightly|lc-ss|lc|path.ipa> [--auto-revoke-oldest] [--json]")
		return ExitUsage
	}
	res, err := InstallIPA(ctx, deps, pos[0], *autoRevoke, func(pct int, stage string) {
		if !*asJSON {
			fmt.Fprintf(stderr, "[%3d%%] %s\n", pct, stage)
		}
	})
	if err != nil {
		return emitErr(*asJSON, err, stdout, stderr)
	}
	if *asJSON {
		return emitJSON(stdout, res)
	}
	fmt.Fprintf(stdout, "Installed %s\nNext: %s\n", res.BundleID, res.Next)
	return ExitOK
}

func runAccount(ctx context.Context, args []string, deps Deps, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: koiside account <status|certs|appids> [--json]")
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("account "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return ExitUsage
	}
	switch sub {
	case "status", "certs", "appids":
		res, err := GetAccountStatus(ctx, deps, sub != "status")
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		if !res.SignedIn {
			fmt.Fprintf(stdout, "Not signed in (Anisette: %s)\n", res.AnisetteURL)
			return ExitOK
		}
		fmt.Fprintf(stdout, "Signed in: %s (%s)\n", res.Email, res.TeamKind)
		if sub == "certs" {
			for _, c := range res.Certificates {
				fmt.Fprintf(stdout, "  %s · %s · Machine=%s · localKey=%v\n", c.SerialNumber, c.Name, c.MachineName, c.HasLocalKey)
			}
		} else if sub == "appids" {
			if res.QuotaKnown {
				fmt.Fprintf(stdout, "7-day App ID quota remaining: %d / %d\n", res.AppIDsAvailable, res.AppIDsMax)
			}
			for _, id := range res.AppIDs {
				fmt.Fprintf(stdout, "  %s (%s)\n", id.Identifier, id.Name)
			}
		}
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown account subcommand %q\n", sub)
		return ExitUsage
	}
}

func runStore(ctx context.Context, args []string, deps Deps, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: koiside store <login|status|switch|logout|search|versions|download|install> ...")
		return ExitUsage
	}
	deps = deps.withDefaults()
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		fs := flag.NewFlagSet("store status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		res, err := GetStoreStatus(ctx, deps)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		if !res.SignedIn {
			fmt.Fprintf(stdout, "App Store: not signed in (saved: %d)\n", len(res.Saved))
			return ExitOK
		}
		fmt.Fprintf(stdout, "App Store: %s (%s / storefront=%s)\n", res.Email, res.CountryCode, res.StoreFront)
		for _, s := range res.Saved {
			fmt.Fprintf(stdout, "  %s (%s)\n", s.Email, s.CountryCode)
		}
		return ExitOK

	case "login":
		fs := flag.NewFlagSet("store login", flag.ContinueOnError)
		fs.SetOutput(stderr)
		email := fs.String("email", "", "Apple ID email")
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{"email": true})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if *email == "" && len(pos) > 0 {
			*email = pos[0]
		}
		if strings.TrimSpace(*email) == "" {
			fmt.Fprintln(stderr, "usage: koiside store login --email <apple_id> [--json]")
			return ExitUsage
		}
		fmt.Fprint(stderr, "Apple ID password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		reader := bufio.NewReader(os.Stdin)
		err = deps.Accounts.SignInStore(ctx, *email, string(pwBytes), func(_ context.Context, em string) (string, error) {
			fmt.Fprintf(stderr, "2FA verification code for %s: ", em)
			line, rErr := reader.ReadString('\n')
			if rErr != nil && len(line) == 0 {
				return "", rErr
			}
			return strings.TrimSpace(line), nil
		})
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		res, err := GetStoreStatus(ctx, deps)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Signed in to App Store: %s (%s)\n", res.Email, res.CountryCode)
		return ExitOK

	case "switch":
		fs := flag.NewFlagSet("store switch", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside store switch <email> [--json]")
			return ExitUsage
		}
		_ = deps.Accounts.RestoreStoreSession(ctx)
		if err := deps.Accounts.SwitchStoreAccount(pos[0]); err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		res, _ := GetStoreStatus(ctx, deps)
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Switched active App Store account to %s (%s)\n", res.Email, res.CountryCode)
		return ExitOK

	case "logout":
		fs := flag.NewFlagSet("store logout", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		deps.Accounts.SignOutStore()
		if *asJSON {
			return emitJSON(stdout, map[string]any{"signed_in": false})
		}
		fmt.Fprintln(stdout, "Signed out of App Store")
		return ExitOK

	case "search":
		fs := flag.NewFlagSet("store search", flag.ContinueOnError)
		fs.SetOutput(stderr)
		country := fs.String("country", "", "App Store country code (e.g. US, JP, CN)")
		entity := fs.String("entity", "software", "entity: software or iPadSoftware")
		limit := fs.Int("limit", 15, "max results")
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{"country": true, "entity": true, "limit": true})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside store search <query> [--country US] [--limit 15] [--json]")
			return ExitUsage
		}
		apps, err := SearchStoreApps(ctx, deps, strings.Join(pos, " "), *country, *entity, *limit)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, apps)
		}
		for _, a := range apps {
			fmt.Fprintf(stdout, "%d\t%s\t%s\tv%s\t%s\n", a.ID, a.BundleID, a.Name, a.Version, a.FormattedPrice)
		}
		return ExitOK

	case "versions":
		fs := flag.NewFlagSet("store versions", flag.ContinueOnError)
		fs.SetOutput(stderr)
		country := fs.String("country", "", "App Store country code")
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{"country": true})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside store versions <bundle_id|track_id> [--country US] [--json]")
			return ExitUsage
		}
		res, err := ListStoreVersions(ctx, deps, pos[0], *country)
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "%s (%s · v%s)\n", res.App.Name, res.App.BundleID, res.App.Version)
		for _, v := range res.Versions {
			fmt.Fprintln(stdout, " ", v)
		}
		return ExitOK

	case "download":
		fs := flag.NewFlagSet("store download", flag.ContinueOnError)
		fs.SetOutput(stderr)
		country := fs.String("country", "", "App Store country code")
		ver := fs.String("version", "", "external version ID")
		outPath := fs.String("o", "", "output IPA path")
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{"country": true, "version": true, "o": true})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside store download <bundle_id|track_id> [--version id] [-o out.ipa] [--json]")
			return ExitUsage
		}
		res, err := DownloadStoreApp(ctx, deps, pos[0], *ver, *country, *outPath, false, func(p appstore.DownloadProgress) {
			if !*asJSON && p.Total > 0 {
				fmt.Fprintf(stderr, "\rDownloading: %d%% (%d / %d bytes)", p.Downloaded*100/p.Total, p.Downloaded, p.Total)
			}
		})
		if !*asJSON {
			fmt.Fprintln(stderr)
		}
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Downloaded %s (%s) -> %s (%d bytes)\n", res.App.Name, res.App.BundleID, res.OutputPath, res.SizeBytes)
		return ExitOK

	case "install":
		fs := flag.NewFlagSet("store install", flag.ContinueOnError)
		fs.SetOutput(stderr)
		country := fs.String("country", "", "App Store country code")
		ver := fs.String("version", "", "external version ID")
		asJSON := fs.Bool("json", false, "output JSON")
		rest, pos := extractPositional(rest, map[string]bool{"country": true, "version": true})
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if len(pos) < 1 {
			fmt.Fprintln(stderr, "usage: koiside store install <bundle_id|track_id|path.ipa> [--version id] [--json]")
			return ExitUsage
		}
		res, err := InstallStoreApp(ctx, deps, pos[0], *ver, *country, false, func(pct int, stage string) {
			if !*asJSON {
				fmt.Fprintf(stderr, "[%3d%%] %s\n", pct, stage)
			}
		})
		if err != nil {
			return emitErr(*asJSON, err, stdout, stderr)
		}
		if *asJSON {
			return emitJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Installed %s (%s)\nNext: %s\n", res.Name, res.BundleID, res.Next)
		return ExitOK

	default:
		fmt.Fprintf(stderr, "unknown store subcommand %q\n", sub)
		return ExitUsage
	}
}

// extractPositional separates flags from positional arguments so flags like --json
// can appear before or after positional arguments.
func extractPositional(args []string, valueFlags map[string]bool) (flagArgs []string, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue
			}
			if valueFlags[name] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return flagArgs, pos
}

func emitJSON(w io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ExitError
	}
	return ExitOK
}

func emitErr(asJSON bool, err error, stdout, stderr io.Writer) int {
	var ar *ActionRequiredError
	if errors.As(err, &ar) {
		if asJSON {
			_ = emitJSON(stdout, map[string]any{
				"status":  "action_required",
				"reason":  ar.Reason,
				"message": ar.Message,
				"next":    ar.Next,
				"details": ar.Details,
			})
		} else {
			fmt.Fprintln(stderr, ar.Error())
		}
		return ExitActionRequired
	}
	if asJSON {
		_ = emitJSON(stdout, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
	} else {
		fmt.Fprintln(stderr, "error:", err.Error())
	}
	return ExitError
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `KoiSide — macOS iOS Sideloading Assistant

Usage:
  koiside [path.ipa...]                 Launch native GUI window
  koiside mcp                           Start stdio JSON-RPC 2.0 MCP server
  koiside ipa inspect <ipa> [--json]    Inspect IPA encryption, components & risks
  koiside ipa preview <ipa> [flags]     Preview metadata/component edits
  koiside ipa export <ipa> -o <out>     Export modified IPA copy
  koiside device status [--json]        Query connected iPhone, tools, LC apps & logs
  koiside device apps [--sideloaded]    List installed iOS apps
  koiside device devmode enable         Reveal/enable iOS Developer Mode
  koiside device docs ls|rm [path]      List or remove /Documents files
  koiside transfer <ipa> [--to ...]     Transfer IPA via USB AFC (SHA-256 verified)
  koiside pairing place [--export ...]  Place or export RemotePairing/Lockdown files
  koiside install <target|ipa>          Desktop sign & USB install
  koiside account status|certs|appids   Query restored Apple Developer account & quota
  koiside store <cmd>                   App Store login, search, download & USB install`)
}
