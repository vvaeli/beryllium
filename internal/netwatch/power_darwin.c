//go:build darwin && cgo

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include "_cgo_export.h"

static io_connect_t rootPort;

static void powerCallback(void *ref, io_service_t service, natural_t type, void *arg) {
	goPowerMessage(type); // diagnostics: which messages macOS sends
	switch (type) {
	case kIOMessageCanSystemSleep:
		IOAllowPowerChange(rootPort, (long)arg);
		break;
	case kIOMessageSystemWillSleep:
		// Sleep waits for the acknowledgement, so connections are closed
		// first (ROADMAP 7.6).
		goPowerEvent(1);
		IOAllowPowerChange(rootPort, (long)arg);
		break;
	case kIOMessageSystemHasPoweredOn:
		goPowerEvent(2);
		break;
	}
}

int berylPowerRun(void) {
	IONotificationPortRef port;
	io_object_t notifier;
	rootPort = IORegisterForSystemPower(NULL, &port, powerCallback, &notifier);
	if (rootPort == MACH_PORT_NULL) {
		return -1;
	}
	CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(port), kCFRunLoopDefaultMode);
	CFRunLoopRun(); // runs for the life of the process
	return 0;
}
