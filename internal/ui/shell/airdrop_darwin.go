package shell

import "github.com/ebitengine/purego/objc"

// openAirDrop asks AppKit to present its AirDrop chooser on the UI thread.
// A true result means the request was handed to AppKit.
func openAirDrop(path string) bool {
	sel := objc.RegisterName
	sharingService := objc.ID(objc.GetClass("NSSharingService"))
	if sharingService == 0 {
		return false
	}

	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(sel("new"))
	defer pool.Send(sel("drain"))

	newString := sel("stringWithUTF8String:")
	stringClass := objc.ID(objc.GetClass("NSString"))
	serviceName := stringClass.Send(newString, "com.apple.share.AirDrop.send")
	service := sharingService.Send(sel("sharingServiceNamed:"), serviceName)
	if service == 0 {
		return false
	}

	filePath := stringClass.Send(newString, path)
	if filePath == 0 {
		return false
	}
	fileURL := objc.ID(objc.GetClass("NSURL")).Send(sel("fileURLWithPath:"), filePath)
	if fileURL == 0 {
		return false
	}
	items := objc.ID(objc.GetClass("NSArray")).Send(sel("arrayWithObject:"), fileURL)
	if !objc.Send[bool](service, sel("canPerformWithItems:"), items) {
		return false
	}

	app := objc.ID(objc.GetClass("NSApplication")).Send(sel("sharedApplication"))
	if !objc.Send[bool](app, sel("isActive")) {
		app.Send(sel("activateIgnoringOtherApps:"), true)
	}
	service.Send(sel("performWithItems:"), items)
	return true
}
