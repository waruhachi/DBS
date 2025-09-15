#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <strings.h>
#import <substrate.h>
#import <sys/stat.h>
#import <sys/types.h>

static const char *(*orig_getenv)(const char *name);
static const char *hook_getenv(const char *name) {
	if (name) {
		if (!strncmp(name, "DYLD_", 5)) {
			return NULL;
		}
	}
	return orig_getenv ? orig_getenv(name) : NULL;
}

static NSDictionary *(*orig_environment)(id self, SEL _cmd);
static NSDictionary *hook_environment(id self, SEL _cmd) {
	NSDictionary *env = orig_environment ? orig_environment(self, _cmd) : @{};
	if (!env || env.count == 0) return env;
	NSMutableDictionary *filtered = [env mutableCopy];
	NSArray *keys = [env allKeys];
	for (id key in keys) {
		if ([key isKindOfClass:[NSString class]]) {
			NSString *s = (NSString *)key;
			if ([s hasPrefix:@"DYLD_"]) {
				[filtered removeObjectForKey:s];
			}
		}
	}
	return filtered;
}

static bool is_suspicious_path(const char *p) {
	if (!p) return false;
	static const char *needles[] = {
		"MobileSubstrate",
		"Substrate",
		"libsubstrate",
		"TweakInject",
		"SubstrateLoader",
		"systemhook",
	};
	for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
		if (strcasestr(p, needles[i])) return true;
	}
	return false;
}

static bool is_suspicious_fs_path(const char *p) {
	if (!p) return false;
	NSString *path = [NSString stringWithUTF8String:p ?: ""];
	NSString *lower = [path lowercaseString];
	NSArray<NSString *> *needles = @[
		@"/applications/cydia.app",
		@"/applications/sileo.app",
		@"/applications/zebra.app",
		@"/library/mobilesubstrate",
		@"/library/loader",
		@"/usr/lib/substrate",
		@"/etc/apt",
		@"/private/var/lib/apt",
		@"/var/lib/apt",
		@"/var/jb",
		@"/bin/bash",
		@"/usr/bin/ssh",
		@"/bin/sh",
	];
	for (NSString *n in needles) {
		if ([lower containsString:n]) {
			return true;
		}
	}
	return false;
}

static bool is_write_mode_fopen(const char *mode) {
	if (!mode) return false;
	return (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+'));
}
static bool is_write_mode_open(int oflag) {
	return (oflag & O_WRONLY) || (oflag & O_RDWR) || (oflag & O_CREAT) || (oflag & O_TRUNC);
}

static const char *(*orig__dyld_get_image_name)(uint32_t image_index);
static const char *hook__dyld_get_image_name(uint32_t image_index) {
	const char *name = orig__dyld_get_image_name ? orig__dyld_get_image_name(image_index) : NULL;
	if (is_suspicious_path(name)) {
		return "/usr/lib/libobjc.A.dylib";
	}
	return name;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hook_dladdr(const void *addr, Dl_info *info) {
	int r = orig_dladdr ? orig_dladdr(addr, info) : 0;
	if (r != 0 && info && info->dli_fname && is_suspicious_path(info->dli_fname)) {
		info->dli_fname = "/usr/lib/libobjc.A.dylib";
	}
	return r;
}

static const char **(*orig_objc_copyImageNames)(unsigned int *outCount);
static const char **hook_objc_copyImageNames(unsigned int *outCount) {
	const char **names = orig_objc_copyImageNames ? orig_objc_copyImageNames(outCount) : NULL;
	if (!names || !outCount || *outCount == 0) return names;
	for (unsigned int i = 0; i < *outCount; i++) {
		const char *n = names[i];
		if (is_suspicious_path(n)) {
			names[i] = "/usr/lib/libobjc.A.dylib";
		}
	}
	return names;
}

typedef int (*ptrace_t)(int, pid_t, void *, int);
static ptrace_t orig_ptrace;
static int hook_ptrace(int request, pid_t pid, void *addr, int data) {
	(void)pid;
	(void)addr;
	(void)data;
	if (request == 31 /* PT_DENY_ATTACH */) {
		return 0;
	}
	return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static void *(*orig_dlsym)(void *__restrict handle, const char *__restrict symbol);
static void *hook_dlsym(void *__restrict handle, const char *__restrict symbol) {
	if (symbol && (strncmp(symbol, "MSHookFunction", 14) == 0 || strncmp(symbol, "MSHookMessageEx", 15) == 0 || strncmp(symbol, "fishhook_", 9) == 0 || strncmp(symbol, "rebind_symbols", 15) == 0)) {
		return NULL;
	}
	return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

typedef int (*csops_t)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
static csops_t orig_csops;
static int hook_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
	int r = orig_csops ? orig_csops(pid, ops, useraddr, usersize) : -1;
	if (r == 0 && ops == 0x7 && useraddr && usersize >= sizeof(uint32_t)) {
		uint32_t *flags = (uint32_t *)useraddr;
		const uint32_t CS_DEBUGGED = 0x10000000;
		*flags &= ~CS_DEBUGGED;
	}
	return r;
}

typedef int (*stat_t)(const char *, struct stat *);
typedef int (*lstat_t)(const char *, struct stat *);
typedef int (*access_t)(const char *, int);
typedef int (*open_t)(const char *, int, ...);
typedef FILE *(*fopen_t)(const char *, const char *);
static stat_t orig_stat;
static lstat_t orig_lstat;
static access_t orig_access;
static open_t orig_open;
static fopen_t orig_fopen;

static int deny_fs_probe_path(const char *path) {
	errno = ENOENT;
	return -1;
}

static int hook_stat(const char *path, struct stat *buf) {
	if (is_suspicious_fs_path(path)) return deny_fs_probe_path(path);
	return orig_stat ? orig_stat(path, buf) : -1;
}
static int hook_lstat(const char *path, struct stat *buf) {
	if (is_suspicious_fs_path(path)) return deny_fs_probe_path(path);
	return orig_lstat ? orig_lstat(path, buf) : -1;
}
static int hook_access(const char *path, int amode) {
	if (is_suspicious_fs_path(path)) return deny_fs_probe_path(path);
	return orig_access ? orig_access(path, amode) : -1;
}
static int hook_open(const char *path, int oflag, ...) {
	if (is_suspicious_fs_path(path)) return deny_fs_probe_path(path);
	if (path && strncmp(path, "/private/", 9) == 0 && is_write_mode_open(oflag)) return deny_fs_probe_path(path);
	if (!orig_open) return -1;
	if (oflag & O_CREAT) {
		va_list ap;
		va_start(ap, oflag);
		mode_t mode = (mode_t)va_arg(ap, int);
		va_end(ap);
		return orig_open(path, oflag, mode);
	} else {
		return orig_open(path, oflag);
	}
}
static FILE *hook_fopen(const char *path, const char *mode) {
	if (is_suspicious_fs_path(path)) {
		errno = ENOENT;
		return NULL;
	}
	if (path && strncmp(path, "/private/", 9) == 0 && is_write_mode_fopen(mode)) {
		errno = EACCES;
		return NULL;
	}
	return orig_fopen ? orig_fopen(path, mode) : NULL;
}

static BOOL (*orig_fileExistsAtPath)(id self, SEL _cmd, NSString *path);
static BOOL hook_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
	if (!path) return NO;
	if (is_suspicious_fs_path([path fileSystemRepresentation])) return NO;
	return orig_fileExistsAtPath ? orig_fileExistsAtPath(self, _cmd, path) : NO;
}
static BOOL (*orig_fileExistsAtPathIsDir)(id self, SEL _cmd, NSString *path, BOOL *isDir);
static BOOL hook_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
	if (!path) {
		if (isDir) *isDir = NO;
		return NO;
	}
	if (is_suspicious_fs_path([path fileSystemRepresentation])) {
		if (isDir) *isDir = NO;
		return NO;
	}
	return orig_fileExistsAtPathIsDir ? orig_fileExistsAtPathIsDir(self, _cmd, path, isDir) : NO;
}

static BOOL (*orig_canOpenURL)(id self, SEL _cmd, NSURL *url);
static BOOL hook_canOpenURL(id self, SEL _cmd, NSURL *url) {
	if (!url) return NO;
	NSString *scheme = [[url scheme] lowercaseString];
	if (!scheme) return NO;
	if ([scheme isEqualToString:@"cydia"] || [scheme isEqualToString:@"sileo"] || [scheme isEqualToString:@"zbra"] || [scheme isEqualToString:@"apt"] || [scheme isEqualToString:@"filza"]) {
		return NO;
	}
	return orig_canOpenURL ? orig_canOpenURL(self, _cmd, url) : NO;
}

static BOOL retNO(id self, SEL _cmd) {
	(void)self;
	(void)_cmd;
	return NO;
}
static void swizzle_suspicious_bools_app_only(void) {
	const char *selectors[] = {
		"isJailbroken",
		"isDeviceJailbroken",
		"deviceIsJailbroken",
		"isCompromised",
		"deviceIsCompromised",
		"isRooted",
		"rooted",
		"compromised",
		"isCompromiseDetected",
		"isTampered",
		"isDebuggerAttached",
		"debuggerAttached",
	};
	NSString *exePath = [[NSBundle mainBundle] executablePath];
	if (!exePath) return;
	unsigned int classCount = 0;
	const char **classNames = objc_copyClassNamesForImage([exePath fileSystemRepresentation], &classCount);
	if (!classNames || classCount == 0) return;
	for (unsigned int i = 0; i < classCount; i++) {
		const char *name = classNames[i];
		if (!name) continue;
		Class cls = objc_getClass(name);
		if (!cls) continue;
		for (size_t j = 0; j < sizeof(selectors) / sizeof(selectors[0]); j++) {
			SEL sel = sel_getUid(selectors[j]);
			Method m = class_getInstanceMethod(cls, sel);
			if (!m) continue;
			const char *enc = method_getTypeEncoding(m);
			if (!enc) continue;
			if (enc[0] == 'B' || enc[0] == 'c') {
				method_setImplementation(m, (IMP)retNO);
			}
		}
	}
	free(classNames);
}

__attribute__((constructor)) static void _ctf_security_init() {
	void *libSystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
	if (libSystem) {
		void *sym = dlsym(libSystem, "getenv");
		if (sym) {
			MSHookFunction(sym, (void *)&hook_getenv, (void **)&orig_getenv);
		}
		void *dladdr_sym = dlsym(libSystem, "dladdr");
		if (dladdr_sym) {
			MSHookFunction(dladdr_sym, (void *)&hook_dladdr, (void **)&orig_dladdr);
		}
		void *ptrace_sym = dlsym(libSystem, "ptrace");
		if (ptrace_sym) {
			MSHookFunction(ptrace_sym, (void *)&hook_ptrace, (void **)&orig_ptrace);
		}
		void *dlsym_sym = dlsym(libSystem, "dlsym");
		if (dlsym_sym) {
			MSHookFunction(dlsym_sym, (void *)&hook_dlsym, (void **)&orig_dlsym);
		}
		void *csops_sym = dlsym(libSystem, "csops");
		if (csops_sym) {
			MSHookFunction(csops_sym, (void *)&hook_csops, (void **)&orig_csops);
		}
		void *stat_sym = dlsym(libSystem, "stat");
		if (stat_sym) MSHookFunction(stat_sym, (void *)&hook_stat, (void **)&orig_stat);
		void *lstat_sym = dlsym(libSystem, "lstat");
		if (lstat_sym) MSHookFunction(lstat_sym, (void *)&hook_lstat, (void **)&orig_lstat);
		void *access_sym = dlsym(libSystem, "access");
		if (access_sym) MSHookFunction(access_sym, (void *)&hook_access, (void **)&orig_access);
		void *open_sym = dlsym(libSystem, "open");
		if (open_sym) MSHookFunction(open_sym, (void *)&hook_open, (void **)&orig_open);
		void *fopen_sym = dlsym(libSystem, "fopen");
		if (fopen_sym) MSHookFunction(fopen_sym, (void *)&hook_fopen, (void **)&orig_fopen);
	}

	Class procInfoCls = [NSProcessInfo class];
	SEL sel = @selector(environment);
	Method m = class_getInstanceMethod(procInfoCls, sel);
	if (m) {
		orig_environment = (typeof(orig_environment))method_getImplementation(m);
		method_setImplementation(m, (IMP)hook_environment);
	}

	void *libDyld = dlopen("/usr/lib/libdyld.dylib", RTLD_LAZY);
	if (!libDyld) libDyld = dlopen("/usr/lib/system/libdyld.dylib", RTLD_LAZY);
	if (libDyld) {
		void *sym = dlsym(libDyld, "_dyld_get_image_name");
		if (sym) {
			MSHookFunction(sym, (void *)&hook__dyld_get_image_name, (void **)&orig__dyld_get_image_name);
		}
	}

	void *libObjC = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY);
	if (libObjC) {
		void *sym = dlsym(libObjC, "objc_copyImageNames");
		if (sym) {
			MSHookFunction(sym, (void *)&hook_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
		}
	}

	Class fm = objc_getClass("NSFileManager");
	if (fm) {
		Method m1 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
		if (m1) {
			orig_fileExistsAtPath = (typeof(orig_fileExistsAtPath))method_getImplementation(m1);
			method_setImplementation(m1, (IMP)hook_fileExistsAtPath);
		}
		Method m2 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
		if (m2) {
			orig_fileExistsAtPathIsDir = (typeof(orig_fileExistsAtPathIsDir))method_getImplementation(m2);
			method_setImplementation(m2, (IMP)hook_fileExistsAtPathIsDir);
		}
	}

	Class uiapp = objc_getClass("UIApplication");
	if (uiapp) {
		SEL sel = @selector(canOpenURL:);
		Method m3 = class_getInstanceMethod(uiapp, sel);
		if (m3) {
			orig_canOpenURL = (typeof(orig_canOpenURL))method_getImplementation(m3);
			method_setImplementation(m3, (IMP)hook_canOpenURL);
		}
	}

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
		swizzle_suspicious_bools_app_only();
	});
}
